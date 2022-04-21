#!/bin/sh
cd /opt/mautrix-signal

function fixperms {
	chown -R $UID:$GID /data

	# /opt/mautrix-signal is read-only, so disable file logging if it's pointing there.
	if [[ "$(yq e '.logging.handlers.file.filename' /data/config.yaml)" == "./mautrix-signal.log" ]]; then
		yq -I4 e -i 'del(.logging.root.handlers[] | select(. == "file"))' /data/config.yaml
		yq -I4 e -i 'del(.logging.handlers.file)' /data/config.yaml
	fi
}

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
	fixperms
	exit
fi

if [ ! -f /data/registration.yaml ]; then
	python3 -m mautrix_signal -g -c /data/config.yaml -r /data/registration.yaml || exit $?
	echo "Didn't find a registration file."
	echo "Generated one for you."
	echo "See https://docs.mau.fi/bridges/general/registering-appservices.html on how to use it."
	fixperms
	exit
fi

fixperms
exec su-exec $UID:$GID python3 -m mautrix_signal -c /data/config.yaml
