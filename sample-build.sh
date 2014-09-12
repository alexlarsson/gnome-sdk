#!/bin/bash

# Show build commands
set -x

export GNOME_SDK_APP=gedit

# build gtksourceview
git clone git://git.gnome.org/gtksourceview
cd gtksourceview
gnome-sdk ./autogen.sh --prefix=/self
gnome-sdk make -j4
gnome-sdk make install
cd ..

# build libpeas
git clone git://git.gnome.org/libpeas
cd libpeas
gnome-sdk ./autogen.sh --prefix=/self
gnome-sdk make -j4
gnome-sdk make install
cd ..

#build gedit
git clone git://git.gnome.org/gedit
cd gedit
git submodule update --init --recursive
gnome-sdk ./autogen.sh --prefix=/self --disable-spell
gnome-sdk make -j4
gnome-sdk make install

#strip binaries
gnome-sdk bash -c "strip /self/bin/* /self/lib/*.so*"

#remove includes
gnome-sdk rm -rf /self/include

#run gedit
echo You can now run gedit as: gnome-sdk -p -a gedit gedit
echo The app files are in ~/.local/share/gnome-sdk/gedit for easy packaging
