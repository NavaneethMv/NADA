{
  description = "anomalyX";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };
        pythonWithPackages = pkgs.python311.withPackages (ps: with ps; [
          mininet-python
          pip
        ]);
      in {
        devShells.default = pkgs.mkShell {
          name = "anomalyX-dev-shell";

          buildInputs = with pkgs; [
            mininet
            pythonWithPackages
            nodejs_20
            openvswitch
          ];

          shellHook = ''
            echo "Activating Python virtual environment..."
            export PYTHONPATH=${pythonWithPackages}/${pythonWithPackages.sitePackages}
            
            # Create venv if it doesn't exist
            if [ ! -d ".venv" ]; then
              ${pythonWithPackages}/bin/python -m venv .venv
            fi

            source .venv/bin/activate
            pip install --upgrade pip
            
            if [ -f requirements.txt ]; then
              pip install -r requirements.txt
            fi
          '';
        };
      }
    );
}
