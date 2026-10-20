# STE style guide

All text in this project uses Simplified Technical English (ASD-STE100). This guide gives a short summary of the rules. It does not copy the ASD dictionary.

## Where the rules apply

The rules apply to all text that a person reads:

- CLI help and messages
- Code comments and doc comments
- Templates, reports, and rules-pack text
- The README and all documents
- Commit messages and pull request descriptions

## The rules

1. Write an instruction in 20 words or fewer.
2. Write a description in 25 words or fewer.
3. Write 6 sentences or fewer in a paragraph.
4. Use the active voice.
5. Put one instruction in each sentence.
6. Use a simple word. Use the same word for the same thing.
7. Use the simple present tense when you can.
8. Do not use a word from the project word list below. Use the word that the list gives.

## Checks

The Vale tool checks the rules with the files in `.github/vale/STE/`.

- `SentenceLength` finds a sentence with more than 25 words.
- `ProceduralLength` finds a list item with more than 20 words.
- `ParagraphLength` finds a paragraph with more than 6 sentences.
- `Passive` finds a form of `be` with a past participle.
- `Words` finds a word from the project word list.

To make the text files for the check, run `cargo xtask strings --out target/ste`. Then run Vale on the files in `target/ste/`.

## Project word list

Use the word in the second column.

| Do not use | Use |
| --- | --- |
| `utilize` | `use` |
| `ensure` | `make sure` |
| `perform` | `do` |
| `in order to` | `to` |
| `prior to` | `before` |
| `commence`, `initiate` | `start` |
| `terminate` | `stop` |
| `require` | `need` |
| `indicate`, `display` | `show` |
| `modify` | `change` |
| `obtain` | `get` |
| `provide` | `give` |
| `verify` | `check` |

The file `.github/vale/STE/Words.yml` holds the full list. Change the list and the file together.

## Technical names

You can use a technical name, also if it is not a simple word. The names in this list are in code format in the text:

- Algorithm names: `ML-KEM`, `ML-DSA`, `SLH-DSA`, `Ed25519`, `RSA`, `ECDSA`, `X25519`, `AES`, `SHA-256`
- File names: `scope.toml`, `Cargo.toml`, `.pqr`, `CBOM`
- Command names: `pqaudit`, `scan files`, `scan net`, `init`, `merge`, `report`, `cbom`, `explain`, `rules`, `profiles`
- Flag names: `--engagement`, `--quiet`, `--verbose`, `--log-format`, `--no-color`, `--allow-unsigned-rules`

## Commit messages

- Write the subject line in the imperative form. Example: `Add the SSH probe`.
- Do not put a type prefix in front of the subject.
- Write the subject in 72 characters or fewer.
- Write the body in STE. The body is optional.

## Examples

Each example shows the text before and after the change.

Example 1. Use a short sentence.

```text
Before: In order to start the scan, the operator must first make sure that the scope file exists and that it lists each host.
After: Make sure that the scope file exists. Make sure that it lists each host. Then start the scan.
```

Example 2. Use the active voice.

```text
Before: The results file is written by the tool.
After: The tool writes the results file.
```

Example 3. Use a simple word.

```text
Before: Utilize the flag to modify the output.
After: Use the flag to change the output.
```

Example 4. Put one instruction in each sentence.

```text
Before: Open the file and read the key and write the length to the log.
After: Open the file. Read the key. Write the length to the log.
```

Example 5. Keep a paragraph short.

```text
Before: A paragraph with ten sentences that each give one more detail.
After: Two paragraphs with five sentences each. Each paragraph has one topic.
```
