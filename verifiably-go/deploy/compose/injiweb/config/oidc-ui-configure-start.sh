#!/bin/bash

# Patched version of mosipid/oidc-ui:1.5.1's configure_start.sh.
# The upstream script deletes $plugins_path/temp after extracting the
# sign-in plugin, so on a container *restart* (same filesystem layer)
# the cd into temp/ fails and the container crash-loops.
# This version skips work that has already been done.

set -e

echo "Downloading pre-requisites started."

# Check if $i18n_url_env is not empty
if [[ -n "$i18n_url_env" ]]; then
    echo "i18n_url_env is set: $i18n_url_env"
    wget --no-check-certificate --no-cache --no-cookies $i18n_url_env -O $i18n_path/esignet-i18n-bundle.zip

    echo "unzip i18n bundle files.."
    chmod 775 $i18n_path/*
    cd $i18n_path
    unzip -o esignet-i18n-bundle.zip
    rm esignet-i18n-bundle.zip
    echo "unzip i18n bundle completed."
fi

# Check if $theme_url_env is not empty
if [[ -n "$theme_url_env" ]]; then
    echo "theme_url_env is set: $theme_url_env"
    wget --no-check-certificate --no-cache --no-cookies $theme_url_env -O $theme_path/esignet-theme.zip

    echo "unzip theme files.."
    chmod 775 $theme_path/*
    cd $theme_path
    unzip -o esignet-theme.zip
    rm esignet-theme.zip
    echo "unzip theme completed."
fi

# Check if $images_url_env is not empty
if [[ -n "$images_url_env" ]]; then
    echo "images_url_env is set: $images_url_env"
    wget --no-check-certificate --no-cache --no-cookies $images_url_env -O $image_path/esignet-image.zip

    echo "unzip image files.."
    chmod 775 $image_path/*
    cd $image_path
    unzip -o esignet-image.zip
    rm esignet-image.zip
    echo "unzip image completed."
fi

# sign-in-button-plugin — idempotent: skip if already extracted
if [[ -f "$plugins_path/sign-in-button-plugin.js" ]]; then
    echo "sign-in-button-plugin.js already exists, skipping extraction."
else
    echo "unzip plugins.."
    cd $plugins_path/temp
    unzip -o sign-in-button-plugin.zip
    rm sign-in-button-plugin.zip
    mv $plugins_path/temp/sign-in-with-esignet/$plugins_format/index.js $plugins_path/sign-in-button-plugin.js
    cd $plugins_path
    rm -r temp
fi

echo "Pre-requisites download completed."

echo "Replacing public url placeholder with public url"

workingDir=$nginx_dir/html
if [[ -z "$OIDC_UI_PUBLIC_URL" ]]; then
  rpCmd="s/_PUBLIC_URL_//g"
  grep -rl '_PUBLIC_URL_' $workingDir | xargs sed -i $rpCmd 2>/dev/null || true
else
  workingDir=$nginx_dir/${OIDC_UI_PUBLIC_URL}
  mkdir -p $workingDir
  mv  -v $nginx_dir/html/* $workingDir/ 2>/dev/null || true
  rpCmd="s/_PUBLIC_URL_/\/${OIDC_UI_PUBLIC_URL}/g"
  grep -rl '_PUBLIC_URL_' $workingDir | xargs sed -i $rpCmd 2>/dev/null || true
fi

echo "Replacing completed."

echo "generating env-config file"

echo "window._env_ = {" > ${workingDir}/env-config.js
awk -F '=' '{ print $1 ": \"" (ENVIRON[$1] ? ENVIRON[$1] : $2) "\"," }' ${workingDir}/env.env >> ${workingDir}/env-config.js
echo "}" >> ${workingDir}/env-config.js

echo "generation of env-config file completed!"

exec "$@"
