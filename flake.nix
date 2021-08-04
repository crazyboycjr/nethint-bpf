{
  description = "NetHint BPF";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs?rev=388fa59b1db24c031667e8c8eab41c7e606a3ca3";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        {
          devShell = import ./shell.nix { inherit pkgs; };
        }
      );
}
