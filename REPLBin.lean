/-
  Copyright (c) 2021 Microsoft Corporation. All rights reserved.
  Released under Apache 2.0 license as described in the file LICENSE.
  Authors: Alexander Bentkamp, Arthur Paulino, Daniel Selsam

  A simple REPL environment for Lean 4 that also supports meta-commands
  (commands starting with '!').
-/

import Lean
import Std
import REPLLib

open Lean Lean.Elab Lean.Elab.Command Std

def main (args: List String): IO Unit := do
  -- initSearchPath (← findSysroot?)
  -- let imports ← buildImports args
  IO.print "> "
  let code ←  (← (← IO.getStdin).getLine)
  let state ← mk_init_state
  let (val, out, err, state) ← runCode state code
  IO.println $ "val: |" ++ val  ++ "|"
  IO.println $ "out: |" ++ out  ++ "|"
  IO.println $ "err: |" ++ err  ++ "|"

