# This Source Code Form is subject to the terms of the Mozilla Public License,
# v. 2.0. If a copy of the MPL was not distributed with this file, You can
# obtain one at https://mozilla.org/MPL/2.0/.

{
  inputs.nixpkgs.url = "github:nixos/nixpkgs";

  outputs = { self, nixpkgs }: {
    devShell.x86_64-linux =
      let pkgs = import nixpkgs { system = "x86_64-linux"; };
      in pkgs.mkShell {
        buildInputs = with pkgs; [ gprbuild gnat libargon2 gdb ];
      };
  };
}
