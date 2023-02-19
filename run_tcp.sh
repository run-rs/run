#!/bin/bash

FLAGS=$(getopt --long update, client,trace,period: -- "$@")

[ $? -eq 0 ] || {
  echo "Incorrect options provided"
  exit 1
}

eval set  "$FLAGS" --

update=false
client=false
trace=false
period=10
buffer_size=9000

while true; do
  case "$1" in
  --update ) update=true;shift;;
  --client ) client=true;shift;;
  --trace ) trace=true;shift;; 
  --period ) shift; period=$1; shift;;
  --buf_size ) shift; buffer_size=$1; shift;;
  -- ) break;;
  esac
done

echo "set period $period"

if [ ! -d "install" ] || $update ; then
  echo "install examples ..."
  cargo install --path examples --root install --examples -q >/dev/null 2>&1
  echo "done"
else
  echo "already installed"
fi



# launch run_tcp
if $client ; then
  if $trace ; then
    sudo RUST_LOG=trace RUST_BACKTRACE=1 install/bin/run_tcp --client --period=$period --buf-size=$buffer_size
  else
    sudo install/bin/run_tcp --client --period=$period --buf-size=$buffer_size
  fi
else
  if $trace ; then
    sudo RUST_LOG=trace RUST_BACKTRACE=1 install/bin/run_tcp --period=$period --buf-size=$buffer_size
  else
    sudo install/bin/run_tcp --period=$period --buf-size=$buffer_size
  fi
fi

  


