// Preloaded with --import when capturing proof output: the CLI only prints
// ANSI styles to a terminal, and a captured pipe is not one. Nothing else in
// the CLI's behaviour depends on this flag once --non-interactive is passed.
process.stdout.isTTY = true;
