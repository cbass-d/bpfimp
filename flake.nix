{
	description = "bpfimp dev environment";

	inputs = {
		nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

		rust-overlay = {
			url = "github:oxalica/rust-overlay";
			inputs.nixpkgs.follows = "nixpkgs";
		};
	};

	outputs = { self, nixpkgs, rust-overlay }:
		let
			system = "x86_64-linux";
			pkgs = import nixpkgs {
				inherit system;
				overlays = [ rust-overlay.overlays.default ];
			};
			rust-toolchain = pkgs.rust-bin.selectLatestNightlyWith (toolchain:
				toolchain.default.override {
					extensions = [ "rust-src" ];
				});
			rustupShim = pkgs.writeShellScriptBin "rustup" ''
				if [ "$1" = "run" ]; then
					shift 2
				fi
				exec "$@"
			'';

			bpf-linker = pkgs.bpf-linker.override {
				llvmPackagesForLinker = pkgs.llvmPackages_22;
			};
		in
		{
			devShells.${system}.default = pkgs.mkShell {
				packages = [
					rustupShim
					rust-toolchain
					bpf-linker
				];
			};
		};
}
