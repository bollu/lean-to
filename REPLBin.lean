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

partial def mainLoop (state: State) : IO Unit := do
  IO.print "> "
  let code ←  (← (← IO.getStdin).getLine)
  let (val, out, err, state) ← runCode state code
  IO.println $ "val: |" ++ val  ++ "|"
  IO.println $ "out: |" ++ out  ++ "|"
  IO.println $ "err: |" ++ err  ++ "|"
  mainLoop state

def main (args: List String): IO Unit := do
  -- initSearchPath (← findSysroot?)
  -- let imports ← buildImports args
  mainLoop  (← mk_init_state)

