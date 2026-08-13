FROM eclipse-temurin:11-jdk

RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump curl ca-certificates php-cli python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# weevely runtime deps (CLI entry lives in the mounted tools dir)
RUN pip install --no-cache-dir --break-system-packages \
      prettytable Mako PyYAML python-dateutil PySocks pyOpenSSL argcomplete telnetlib3

# Tomcat 8.5 (Java 8 compatible) from the Apache archive
RUN curl -fsSL -o /opt/tomcat.tar.gz \
      https://archive.apache.org/dist/tomcat/tomcat-8/v8.5.100/bin/apache-tomcat-8.5.100.tar.gz \
    && mkdir -p /opt/tomcat \
    && tar -xzf /opt/tomcat.tar.gz -C /opt/tomcat --strip-components=1 \
    && rm -f /opt/tomcat.tar.gz

# Self-signed keystore for the HTTPS connector (client trusts everything anyway)
RUN keytool -genkeypair -alias tomcat -keyalg RSA -keysize 2048 -validity 3650 \
      -dname "CN=localhost, OU=lab, O=lab, C=CN" \
      -keystore /opt/tomcat/conf/keystore.jks -storepass changeit -keypass changeit

WORKDIR /lab
CMD ["/bin/bash"]
