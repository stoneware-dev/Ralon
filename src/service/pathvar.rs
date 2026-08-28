//! Adding and removing one directory in a `PATH` value, as text.
//!
//! Separated from the registry call that reads and writes it, because this is
//! the half that can be wrong in a way nobody notices for a week. The usual way
//! to do this from a script is `setx PATH ...`, which truncates the value at
//! 1024 characters — a developer's `PATH` is routinely longer than that, and the
//! damage is silent, immediate and permanent. So nothing here shortens anything:
//! [`with`] appends one entry, [`without`] removes one entry, everything else in
//! the string comes back byte for byte, and both return `None` when there was
//! nothing to do rather than rewriting an identical value.
//!
//! Windows spelling throughout — `;` as the separator, case-insensitive
//! comparison — because Windows is the only platform where Ralon edits `PATH`
//! at all. A shell's `PATH` on macOS lives in whichever startup file that shell
//! reads, which is a guess, and a tool that guesses wrong has appended a line to
//! a file the developer maintains by hand.

// Compiled and *tested* on every platform, called on one. That is the same rule
// the rest of this project follows — planning is platform-independent so it can
// be checked where the syscalls cannot run — and the alternative, gating the
// module on Windows, would mean the one part of this that can silently corrupt a
// developer's environment is only ever exercised by a third of CI.
#![cfg_attr(not(windows), allow(dead_code))]

const SEPARATOR: char = ';';

/// `value` with `directory` appended, or `None` if it is already present.
///
/// Appended rather than prepended, and that is a decision rather than a
/// convenience. The directory Ralon adds holds a *snapshot* of the binary, taken
/// when `install` ran. A package manager's copy is the one that upgrades, so it
/// has to win when both exist — otherwise `ralon --version` would report the
/// staged copy forever and an upgrade would appear not to have happened.
pub fn with(value: &str, directory: &str) -> Option<String> {
    if entries(value).any(|entry| same(entry, directory)) {
        return None;
    }
    if value.is_empty() {
        return Some(directory.to_string());
    }
    // Always a separator, even when the value already ends with one. Filling
    // that trailing slot instead looks tidier and is wrong: a value ending in
    // `;` has an empty final entry, `with` would consume it, and `without` has
    // no way to know it should put one back — so an install followed by an
    // uninstall quietly shortened the user's `PATH`. Caught on a real machine,
    // by reading the registry back rather than trusting the return code.
    Some(format!("{value}{SEPARATOR}{directory}"))
}

/// `value` without `directory`, or `None` if it was not there.
///
/// Removes only entries that name this directory. Everything else — including
/// empty entries, which mean "the current directory" and are somebody's
/// deliberate choice — survives in its original position.
pub fn without(value: &str, directory: &str) -> Option<String> {
    if !entries(value).any(|entry| same(entry, directory)) {
        return None;
    }
    let kept: Vec<&str> = entries(value)
        .filter(|entry| !same(entry, directory))
        .collect();
    Some(kept.join(";"))
}

fn entries(value: &str) -> impl Iterator<Item = &str> {
    value.split(SEPARATOR)
}

/// Whether two `PATH` entries name the same directory.
///
/// Compared leniently on purpose. The same directory is written `C:\X`, `c:\x`,
/// `C:\X\` and `"C:\X"` by different installers, and treating those as different
/// would mean `install` appending a duplicate every time it runs and `uninstall`
/// leaving one behind.
fn same(entry: &str, directory: &str) -> bool {
    fn tidy(text: &str) -> &str {
        text.trim()
            .trim_matches('"')
            .trim_end_matches(['\\', '/'])
            .trim()
    }
    let (entry, directory) = (tidy(entry), tidy(directory));
    !entry.is_empty() && entry.eq_ignore_ascii_case(directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIN: &str = r"C:\Users\me\AppData\Local\Ralon\bin";

    #[test]
    fn adding_appends_rather_than_prepending() {
        // Order decides which binary a shell runs. The package manager's copy is
        // the one that gets upgraded, so it has to come first.
        let value = with(r"C:\Windows;C:\Users\me\.bun\bin", BIN).unwrap();
        assert_eq!(value, format!(r"C:\Windows;C:\Users\me\.bun\bin;{BIN}"));
    }

    #[test]
    fn adding_twice_changes_nothing() {
        // `ralon install` is documented as safe to re-run. Without this it would
        // grow the value by one entry every time.
        let once = with(r"C:\Windows", BIN).unwrap();
        assert_eq!(with(&once, BIN), None);
    }

    #[test]
    fn a_different_spelling_of_the_same_directory_is_the_same_entry() {
        for spelling in [
            r"c:\users\me\appdata\local\ralon\bin",
            r"C:\Users\me\AppData\Local\Ralon\bin\",
            "\"C:\\Users\\me\\AppData\\Local\\Ralon\\bin\"",
        ] {
            let value = format!(r"C:\Windows;{spelling}");
            assert_eq!(with(&value, BIN), None, "{spelling} was added again");
            assert!(
                without(&value, BIN).is_some(),
                "{spelling} was left behind by uninstall"
            );
        }
    }

    #[test]
    fn removing_takes_out_exactly_one_entry() {
        let value = format!(r"C:\Windows;{BIN};C:\Users\me\.bun\bin");
        assert_eq!(
            without(&value, BIN).unwrap(),
            r"C:\Windows;C:\Users\me\.bun\bin"
        );
    }

    #[test]
    fn removing_something_that_is_not_there_reports_nothing_to_do() {
        // So `uninstall` never writes the registry — and never risks the value —
        // over a directory it did not add.
        assert_eq!(without(r"C:\Windows;C:\Other", BIN), None);
    }

    #[test]
    fn nothing_else_in_the_value_is_disturbed() {
        // The failure this module exists to avoid, asserted directly: a PATH
        // longer than `setx` would keep, put through both operations, has to come
        // back exactly as it went in.
        let long: Vec<String> = (0..200).map(|index| format!(r"C:\dir{index}")).collect();
        // Ends with a separator, because a real one did and that is what broke.
        let original = format!("{};", long.join(";"));
        assert!(original.len() > 1024, "the fixture is not long enough");

        let added = with(&original, BIN).unwrap();
        let removed = without(&added, BIN).unwrap();
        assert_eq!(removed, original);
    }

    #[test]
    fn an_empty_entry_is_somebody_s_choice_and_survives() {
        // An empty entry means the current directory. Dropping it would change
        // what the developer's shell does, in a command about something else.
        let value = format!(r"C:\Windows;;{BIN}");
        assert_eq!(without(&value, BIN).unwrap(), r"C:\Windows;");
    }

    #[test]
    fn an_empty_path_is_handled_without_a_leading_separator() {
        assert_eq!(with("", BIN).unwrap(), BIN);
    }

    #[test]
    fn a_value_that_ends_in_a_separator_comes_back_unchanged() {
        // The real bug this file was written to avoid, and it got in anyway:
        // `with` used to fill the empty entry a trailing `;` leaves, so the
        // round trip returned a value one character shorter than it started.
        // Silent, permanent, and invisible to every test that did not compare
        // the whole string.
        for original in [r"C:\Windows;C:\Users\me\.bun\bin;", r"C:\Windows;", ";"] {
            let added = with(original, BIN).unwrap();
            assert_eq!(
                without(&added, BIN).unwrap(),
                original,
                "the round trip changed `{original}`"
            );
        }
    }
}
