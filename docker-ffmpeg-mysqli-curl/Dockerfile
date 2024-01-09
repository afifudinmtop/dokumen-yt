FROM ubuntu:22.04

# Set non-interactive shell to avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install Apache, PHP 8.1, and necessary packages
RUN apt-get update && apt-get install -y software-properties-common \
    && add-apt-repository ppa:ondrej/php \
    && apt-get update \
    && apt-get install -y \
        apache2 \
        php8.1 \
        libapache2-mod-php8.1 \
        php8.1-mysqli \
        ffmpeg \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Enable Apache PHP and rewrite modules
RUN a2enmod php8.1
RUN a2enmod rewrite

# Manually set up the apache environment variables
ENV APACHE_RUN_USER www-data
ENV APACHE_RUN_GROUP www-data
ENV APACHE_LOG_DIR /var/log/apache2

# Expose apache.
EXPOSE 80

# By default, start up apache in the foreground, override with /bin/bash for interactive.
CMD /usr/sbin/apache2ctl -D FOREGROUND
