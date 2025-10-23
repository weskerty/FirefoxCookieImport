#!/usr/bin/env bash

packages_aptget="nodejs npm"
packages_pacman="nodejs npm"








pkg_manager=""
install_command=""

if pacman -V &>/dev/null; then
    pkg_manager="pacman"
    install_command="sudo pacman -S --needed --noconfirm $packages_pacman"
elif apt-get -v &>/dev/null; then
    pkg_manager="apt-get"
    install_command="sudo apt-get install -y $packages_aptget"
else
    echo "❌Need Install Manual: $packages_aptget/$packages_pacman"
    exit 1
fi

echo "📦 $pkg_manager"

echo "🔧 Preparando Recursos..."
eval $install_command

echo "🚀 Ejecutando..."
npm install && node index.js
