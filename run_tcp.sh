#!/bin/bash

FLAGS=$(getopt --long update, client,trace -- "$@")

[ $? -eq 0 ] || {
  echo "Incorrect options provided"
  exit 1
}

eval set  "$FLAGS" --

update=false
client=false
trace=false


while true; do
  case "$1" in
  --update ) update=true;shift;;
  --client ) client=true;shift;;
  --trace ) trace=true;shift;; 
  -- ) break;;
  esac
done

if [ ! -d "install" ] || $update ; then
  echo "install examples ..."
  cargo install --path examples --root install --examples -q >/dev/null 2>&1
  echo "done"
else
  echo "already installed"
fi



# launch run_tcp
echo "running pbuf...."
if $client ; then
  if $trace ; then
    sudo RUST_LOG=trace RUST_BACKTRACE=1 install/bin/run_tcp --client --period=40 --buf-size=60000 --mtu=1518 > run_tcp.log 2>&1
  else
    sudo install/bin/run_tcp --client --period=30 --buf-size=60000 --mtu=1518 > run_tcp.log 2>&1
  fi
else
  if $trace ; then
    sudo RUST_LOG=trace RUST_BACKTRACE=1 install/bin/run_tcp --period=40 --buf-size=60000 --mtu=1518 > run_tcp.log 2>&1
  else
    sudo install/bin/run_tcp --period=60 --buf-size=60000 --mtu=1518 > run_tcp.log 2>&1
  fi
fi
echo "done"


echo "running cursor...."
if $client ; then
  if $trace ; then
    sudo RUST_LOG=trace RUST_BACKTRACE=1 install/bin/run_tcp_cursor --client --period=40 --buf-size=60000 --mtu=1518 > run_tcp_cursor.log 2>&1
  else
    sudo install/bin/run_tcp_cursor --client --period=30 --buf-size=60000 --mtu=1518 > run_tcp_cursor.log 2>&1
  fi
else
  if $trace ; then
    sudo RUST_LOG=trace RUST_BACKTRACE=1 install/bin/run_tcp_cursor --period=40 --buf-size=60000 --mtu=1518 > run_tcp_cursor.log 2>&1
  else
    sudo install/bin/run_tcp_cursor --period=60 --buf-size=60000 --mtu=1518 > run_tcp_cursor.log 2>&1
  fi
fi
echo "done"

echo "running smoltcp...."
if $client ; then
  if $trace ; then
    sudo RUST_LOG=trace RUST_BACKTRACE=1 install/bin/smol_tcp --client --period=40 --buf-size=60000 --mtu=1518 > smol_tcp.log 2>&1
  else
    sudo install/bin/smol_tcp --client --period=30 --buf-size=60000 --mtu=1518 > smol_tcp.log 2>&1
  fi
else
  if $trace ; then
    sudo RUST_LOG=trace RUST_BACKTRACE=1 install/bin/smol_tcp --period=40 --buf-size=60000 --mtu=1518 > smol_tcp.log 2>&1
  else
    sudo install/bin/smol_tcp --period=60 --buf-size=60000 --mtu=1518 > smol_tcp.log 2>&1
  fi
fi
echo "done"


echo "running pnet...."
if $client ; then
  if $trace ; then
    sudo RUST_LOG=trace RUST_BACKTRACE=1 install/bin/pnet_tcp --client --period=40 --buf-size=60000 --mtu=1518 > pnet_tcp.log 2>&1
  else
    sudo install/bin/pnet_tcp --client --period=30 --buf-size=60000 --mtu=1518 > pnet_tcp.log 2>&1
  fi
else
  if $trace ; then
    sudo RUST_LOG=trace RUST_BACKTRACE=1 install/bin/pnet_tcp --period=40 --buf-size=60000 --mtu=1518 > pnet_tcp.log 2>&1
  else
    sudo install/bin/pnet_tcp --period=60 --buf-size=60000 --mtu=1518 > pnet_tcp.log 2>&1
  fi
fi
echo "done"


echo "running tso...."
if $client ; then
  if $trace ; then
    #sudo RUST_LOG=trace RUST_BACKTRACE=1 install/bin/run_tso --client --period=40 --buf-size=60000 --mtu=1518 > run_tso.log 2>&1
  else
    #sudo install/bin/run_tso --client --period=30 --buf-size=60000 --mtu=1518 > run_tso.log 2>&1
  fi
else
  if $trace ; then
    #sudo RUST_LOG=trace RUST_BACKTRACE=1 install/bin/run_tso --period=40 --buf-size=60000 --mtu=1518 > run_tso.log 2>&1
  else
    #sudo install/bin/run_tso --period=60 --buf-size=60000 --mtu=1518 > run_tso.log 2>&1
  fi
fi
echo "done"







# plot figures
  


