let
  pkgs = import <nixpkgs> { };
in
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    cargo
    pkg-config
    rust-analyzer
    rustc
    rustfmt
  ];

  buildInputs = with pkgs; [
    libGL
    libxkbcommon
    wayland
    wayland-protocols
    xorg.libX11
    xorg.libXcursor
    xorg.libXi
    xorg.libXrandr
  ];

  LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
    pkgs.libGL
    pkgs.libxkbcommon
    pkgs.wayland
    pkgs.xorg.libX11
    pkgs.xorg.libXcursor
    pkgs.xorg.libXi
    pkgs.xorg.libXrandr
  ];
}
