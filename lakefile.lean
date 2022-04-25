import Lake

open Lake DSL

package REPL {
  libName := "REPLLib"
  binRoot := `REPLBin
  libRoots := #[`REPLLib] 
  supportInterpreter := true -- necessary for RPEL
}
