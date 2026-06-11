{
	description = "bpfimp dev environment";

	inputs = {
		nixpgs.url = "github:NixOS/nixpkgs/nixos-unstable";

		rust-overlay = {
			url = "github:oxicalla/rust-overlay";
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
		in
		{
			devShells.${system}.default = pkgs.mkShell {
			};
		};
}
