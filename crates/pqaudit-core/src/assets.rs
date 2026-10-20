//! Match findings to assets. Build the customer context of a finding.
//!
//! The tool never invents context. A field that the customer did not set is `Unassessed`.

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Serialize;

use crate::engagement::{Asset, Exposure};
use crate::{Location, Tier};

/// A context value that is either set by the customer or not assessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Ctx<T> {
    /// The customer set this value.
    Assessed(T),
    /// The customer did not set this value.
    Unassessed,
}

impl<T> Ctx<T> {
    /// Make a value from an optional setting. A missing setting gives `Unassessed`.
    pub fn from_option(value: Option<T>) -> Self {
        value.map_or(Self::Unassessed, Self::Assessed)
    }

    /// Return true if the customer did not set the value.
    pub fn is_unassessed(&self) -> bool {
        matches!(self, Self::Unassessed)
    }

    /// Borrow the value, if the customer set it.
    pub fn as_assessed(&self) -> Option<&T> {
        match self {
            Self::Assessed(value) => Some(value),
            Self::Unassessed => None,
        }
    }
}

/// The customer context of a finding. Each field is `Unassessed` when no asset gives it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AssetContext {
    /// The classification of the data, in the scheme of the customer.
    pub classification: Ctx<String>,
    /// The number of years that the data must stay secret.
    pub data_lifespan_years: Ctx<u32>,
    /// How far the asset is open to attack.
    pub exposure: Ctx<Exposure>,
    /// The tier that selects the deadline milestones.
    pub priority_tier: Ctx<Tier>,
    /// True if a vendor supplies the asset.
    pub vendor: Ctx<bool>,
    /// True if the fix needs a hardware change.
    pub hardware_constrained: Ctx<bool>,
    /// The business unit of the asset. The reports use it to group results.
    pub business_unit: Option<String>,
    /// The owner of the asset.
    pub owner: Option<String>,
}

impl AssetContext {
    /// The context of a finding that matches no asset.
    pub fn unassessed() -> Self {
        Self {
            classification: Ctx::Unassessed,
            data_lifespan_years: Ctx::Unassessed,
            exposure: Ctx::Unassessed,
            priority_tier: Ctx::Unassessed,
            vendor: Ctx::Unassessed,
            hardware_constrained: Ctx::Unassessed,
            business_unit: None,
            owner: None,
        }
    }

    /// The context that an asset gives. A setting that the asset does not have stays `Unassessed`.
    pub fn from_asset(asset: &Asset) -> Self {
        Self {
            classification: Ctx::from_option(asset.classification.clone()),
            data_lifespan_years: Ctx::from_option(asset.data_lifespan_years),
            exposure: Ctx::from_option(asset.exposure),
            priority_tier: Ctx::from_option(asset.priority_tier),
            vendor: Ctx::from_option(asset.vendor),
            hardware_constrained: Ctx::from_option(asset.hardware_constrained),
            business_unit: asset.business_unit.clone(),
            owner: asset.owner.clone(),
        }
    }

    /// Return true if at least one of the six scoring fields is `Unassessed`.
    pub fn has_unassessed(&self) -> bool {
        self.classification.is_unassessed()
            || self.data_lifespan_years.is_unassessed()
            || self.exposure.is_unassessed()
            || self.priority_tier.is_unassessed()
            || self.vendor.is_unassessed()
            || self.hardware_constrained.is_unassessed()
    }
}

/// Compile the path globs of one asset. Return the first pattern that is not valid as the error.
pub(crate) fn compile_paths(asset: &Asset) -> Result<GlobSet, String> {
    let mut builder = GlobSetBuilder::new();
    for pattern in &asset.matcher.paths {
        let glob = Glob::new(pattern).map_err(|_| pattern.clone())?;
        builder.add(glob);
    }
    builder.build().map_err(|_| asset.matcher.paths.join(","))
}

/// The assets with their path globs compiled once.
pub(crate) struct AssetIndex<'a> {
    entries: Vec<(&'a Asset, GlobSet)>,
}

impl<'a> AssetIndex<'a> {
    /// Compile all path globs. A pattern that is not valid never matches here.
    /// The function `assess` checks the patterns before it uses the index.
    pub(crate) fn new(assets: &'a [Asset]) -> Self {
        let entries = assets
            .iter()
            .map(|asset| {
                (
                    asset,
                    compile_paths(asset).unwrap_or_else(|_| GlobSet::empty()),
                )
            })
            .collect();
        Self { entries }
    }

    /// Find the first asset, in file order, that matches the location.
    pub(crate) fn find(&self, loc: &Location) -> Option<&'a Asset> {
        self.position(loc).map(|index| self.entries[index].0)
    }

    /// Find the place in the file order of the first asset that matches the location.
    pub(crate) fn position(&self, loc: &Location) -> Option<usize> {
        self.entries
            .iter()
            .position(|(asset, globs)| matches(asset, globs, loc))
    }
}

fn matches(asset: &Asset, globs: &GlobSet, loc: &Location) -> bool {
    match loc {
        Location::Endpoint { host, ip, .. } => {
            asset
                .matcher
                .hosts
                .iter()
                .any(|name| name.eq_ignore_ascii_case(host))
                || asset
                    .matcher
                    .cidrs
                    .iter()
                    .any(|net| net.contains(&ip.to_canonical()))
        }
        Location::File { path, .. } => globs.is_match(path),
    }
}

/// Find the asset for a location. The first match in the file order wins.
///
/// A host matches without regard to case. An IP address matches a CIDR range.
/// The tool first converts an IPv4-mapped IPv6 address to IPv4.
/// A file path matches a glob.
pub fn match_asset<'a>(assets: &'a [Asset], loc: &Location) -> Option<&'a Asset> {
    AssetIndex::new(assets).find(loc)
}
