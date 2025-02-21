#!/bin/bash

TARGET_PATH=/app/target/dropbear-2022.83/dropbear

if [[ '--stripped' == $1 ]]; then
    echo "[+] Removing symbols from target..."
    strip --strip-all $TARGET_PATH
fi

echo "[+] Tracing example program..."
pin \
    -unique_logfile \
    -unique_error_file \
    -t $PIN_PLUGINS/pin-trace-x86_64.so \
    -- \
    $TARGET_PATH \
    -r /app/target/host_rsa \
    -F -E -s \
    -p 1234 \
    -P /tmp/dropbear.pid &
sleep 10

# Get proc mappings
/app/scripts/parse_proc_maps.py $(cat /tmp/dropbear.pid) | tee /app/out/proc_maps.jsonl

ss -ntlp
echo "Dropbear PID:" $(cat /tmp/dropbear.pid)
tcpdump --immediate-mode -U -i lo -w /app/out/ssh.pcap 'port 1234' &
sleep 10

echo "[+] Connecting..."
/app/target/dropbear-2022.83/dbclient -y -y -p 1234 -m hmac-sha1 -c aes128-ctr -i /app/target/id_rsa root@127.0.0.1 "echo hello world"
sleep 10

kill -SIGQUIT $(cat /tmp/dropbear.pid)
jobs -p | xargs kill -9

# Build out the packet structures from the pcap
tshark -Ossh -d 'tcp.port==1234,ssh' -r ssh.pcap -T pdml \
    | grep -v '<?xml-stylesheet' \
    | xsltproc \
          --stringparam protocol ssh /app/scripts/struct.xsl - \
          > packets.xml

echo "[+] Generating maps.out from memory map information..."
cat maps.jsonl | jq -r '.name + " " + .low' > maps.out
cat proc_maps.jsonl | jq -r '.name + " " + .low' >> maps.out

echo "[+] Collecting dynamically loaded libraries into sysroot..."
/app/scripts/make_sysroot.sh ./maps.out

echo "[+] Saving <path/to/target> in /app/out/exe..."
echo $TARGET_PATH > ./exe

echo "[+] Running tm-analyze on trace output (this may take a while)..."
cp `ls -S trace.* | head -n 1` trace.out
tm-analyze -i trace.out
mv out/ analyzed/
