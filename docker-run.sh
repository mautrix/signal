#!/bin/sh
cd /opt/mautrix-signal

if [ ! -f /data/config.yaml ]; then
	cp example-config.yaml /data/config.yaml
	yq -I4 e -i 'del(.logging.root.handlers[] | select(. == "file"))' /data/config.yaml
	yq -I4 e -i 'del(.logging.handlers.file)' /data/config.yaml
	yq -I4 e -i '.signal.socket_path = "/signald/signald.sock"' /data/config.yaml
	yq -I4 e -i '.signal.outgoing_attachment_dir = "/signald/attachments"' /data/config.yaml
	yq -I4 e -i '.signal.avatar_dir = "/signald/avatars"' /data/config.yaml
	yq -I4 e -i '.signal.data_dir = "/signald/data"' /data/config.yaml
	echo "Didn't find a config file."
	echo "Copied default config file to /data/config.yaml"
	echo "Modify that config file to your liking."
	echo "Start the container again after that to generate the registration file."
	exit
fi

if [ ! -f /data/registration.yaml ]; then
	python3 -m mautrix_signal -g -c /data/config.yaml -r /data/registration.yaml || exit $?
	echo "Didn't find a registration file."
	echo "Generated one for you."
	echo "See https://docs.mau.fi/bridges/general/registering-appservices.html on how to use it."
	exit
fi

exec python3 -m mautrix_signal -c /data/config.yaml
