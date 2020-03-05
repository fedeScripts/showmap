#!/bin/bash

sudo apt install xmlstarlet -y
path=$(pwd)
sudo ln -sfv "$path"/showmap.sh /usr/bin/showmap
