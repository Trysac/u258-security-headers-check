#!/usr/bin/env node
import process from "node:process";
import { run } from "./cli.js";

// Executable entry point installed by the `bin` field of package.json.
const exitCode = await run(process.argv.slice(2), {
  stdout: (s) => {
    process.stdout.write(s);
  },
  stderr: (s) => {
    process.stderr.write(s);
  },
});

process.exitCode = exitCode;
