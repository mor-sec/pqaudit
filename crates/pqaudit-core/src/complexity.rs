//! The complexity of a fix and the tests that the fix needs.

use pqaudit_rules::pack::{ChangeType, RuleDef, TestType};

use crate::assets::{AssetContext, Ctx};
use crate::engagement::{Exposure, ScoringConfig, Size};
use crate::messages;
use crate::Finding;

/// The lowest sensitivity value that adds a certification test.
const CERTIFICATION_SENSITIVITY: f64 = 0.7;

/// The complexity of the fix for a finding.
#[derive(Debug, Clone, PartialEq)]
pub struct Complexity {
    /// The kind of work that the fix needs.
    pub change_type: ChangeType,
    /// The size of the fix.
    pub size: Size,
    /// The approximate migration time in years.
    pub migration_years: f64,
    /// The reasons for the size.
    pub reasons: Vec<String>,
}

/// The name of a change type, as the rules pack writes it.
pub fn change_type_name(change: ChangeType) -> &'static str {
    match change {
        ChangeType::Config => "config",
        ChangeType::LibraryUpgrade => "library-upgrade",
        ChangeType::CodeChange => "code-change",
        ChangeType::ProtocolPartner => "protocol-partner",
        ChangeType::Hardware => "hardware",
        ChangeType::Vendor => "vendor",
    }
}

/// The name of a size.
pub fn size_name(size: Size) -> &'static str {
    match size {
        Size::S => "S",
        Size::M => "M",
        Size::L => "L",
        Size::XL => "XL",
    }
}

/// The name of a test type.
pub fn test_type_name(test: TestType) -> &'static str {
    match test {
        TestType::Unit => "unit",
        TestType::Integration => "integration",
        TestType::Interop => "interop",
        TestType::Performance => "performance",
        TestType::Certification => "certification",
    }
}

/// The rank of a change type. A higher rank means a harder change (spec section 10.3).
fn rank(change: ChangeType) -> u8 {
    match change {
        ChangeType::Config => 0,
        ChangeType::LibraryUpgrade => 1,
        ChangeType::CodeChange => 2,
        ChangeType::ProtocolPartner => 3,
        ChangeType::Hardware => 4,
        ChangeType::Vendor => 5,
    }
}

fn base_size(change: ChangeType) -> Size {
    match change {
        ChangeType::Config => Size::S,
        ChangeType::LibraryUpgrade | ChangeType::CodeChange => Size::M,
        ChangeType::ProtocolPartner => Size::L,
        ChangeType::Hardware | ChangeType::Vendor => Size::XL,
    }
}

fn bigger(size: Size) -> Size {
    match size {
        Size::S => Size::M,
        Size::M => Size::L,
        Size::L | Size::XL => Size::XL,
    }
}

/// Work out the complexity of the fix for a finding.
///
/// The change type is the hardest of: the type of the rule, a CA certificate, a hardware
/// constraint, and a vendor asset. Partner exposure, or a rule with two or more size
/// impacts, makes the size one step larger.
pub fn assess_complexity(
    f: &Finding,
    rule: &RuleDef,
    ctx: &AssetContext,
    cfg: &ScoringConfig,
) -> Complexity {
    let mut reasons = Vec::new();
    let mut change_type = rule.change_type;
    reasons.push(messages::REASON_CHANGE.replace("{change}", change_type_name(change_type)));

    let mut raise = |to: ChangeType, reason: &str, reasons: &mut Vec<String>| {
        reasons.push(reason.to_string());
        if rank(to) > rank(change_type) {
            change_type = to;
        }
    };
    if f.cert.as_ref().is_some_and(|cert| cert.is_ca) {
        raise(
            ChangeType::ProtocolPartner,
            messages::REASON_CA,
            &mut reasons,
        );
    }
    if ctx.hardware_constrained == Ctx::Assessed(true) {
        raise(
            ChangeType::Hardware,
            messages::REASON_HARDWARE,
            &mut reasons,
        );
    }
    if ctx.vendor == Ctx::Assessed(true) {
        raise(ChangeType::Vendor, messages::REASON_VENDOR, &mut reasons);
    }

    let mut size = base_size(change_type);
    let partner = ctx.exposure == Ctx::Assessed(Exposure::Partner);
    let many_impacts = rule.size_impact.len() >= 2;
    if partner {
        reasons.push(messages::REASON_PARTNER.to_string());
    }
    if many_impacts {
        reasons.push(
            messages::REASON_SIZE_IMPACT.replace("{count}", &rule.size_impact.len().to_string()),
        );
    }
    if partner || many_impacts {
        size = bigger(size);
    }

    let migration_years = cfg.migration_years.get(&size).copied().unwrap_or(0.0);
    reasons.push(
        messages::REASON_SIZE
            .replace("{size}", size_name(size))
            .replace("{years}", &migration_years.to_string()),
    );
    Complexity {
        change_type,
        size,
        migration_years,
        reasons,
    }
}

/// List the tests that the fix needs.
///
/// The list starts with the tests of the rule. Partner exposure adds interoperation tests.
/// A rule with certification tests, or a classification with a value of 0.7 or more,
/// adds certification tests.
pub fn testing_scope(rule: &RuleDef, ctx: &AssetContext, cfg: &ScoringConfig) -> Vec<TestType> {
    let mut tests = rule.testing.clone();
    let mut add = |test: TestType| {
        if !tests.contains(&test) {
            tests.push(test);
        }
    };
    if ctx.exposure == Ctx::Assessed(Exposure::Partner) {
        add(TestType::Interop);
    }
    let sensitive = ctx
        .classification
        .as_assessed()
        .and_then(|class| cfg.classification.get(class))
        .is_some_and(|value| *value >= CERTIFICATION_SENSITIVITY);
    if sensitive {
        add(TestType::Certification);
    }
    tests
}
