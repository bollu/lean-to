import Lake

open Lake DSL

package LeanREPL {
  libName := "REPL"
  binRoot := `REPL
  libRoots := #[`REPL] 
  supportInterpreter := true
}
