#!/bin/bash

sudo apt install xmlstarlet -y
path=$(pwd)
sudo ln -sf "$path"/showmap.sh /usr/bin/showmap
