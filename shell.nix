let
	pkgs = import <nixpkgs> {};
	py = pkgs.python38Packages;
in

pkgs.mkShell {
					nativeBuildInputs = [ py.pyzmq py.jupyter_console pkgs.jupyter ];
}
