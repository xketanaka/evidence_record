# Development / test environment for evidence_record.
ARG RUBY_VERSION=3.4
FROM ruby:${RUBY_VERSION}-slim

# A JDK for the interoperability tests with Bouncy Castle (docker compose run
# --rm interop).
ARG INSTALL_JDK=false
RUN if [ "$INSTALL_JDK" = "true" ]; then \
      apt-get update \
      && apt-get install -y --no-install-recommends default-jdk-headless \
      && rm -rf /var/lib/apt/lists/*; \
    fi

# Containers run as the host user (see docker-compose.yml), so HOME and the gem
# directory must be writable by any user.
ENV HOME=/tmp \
    BUNDLE_PATH=/usr/local/bundle

WORKDIR /app

# Install gems in the image. Only the files bundler needs are copied, so the
# layer is rebuilt only when the dependencies change.
COPY Gemfile evidence_record.gemspec ./
COPY lib/evidence_record/version.rb lib/evidence_record/
RUN bundle install --jobs 4 \
 && chmod -R a+rwX /usr/local/bundle

CMD ["bundle", "exec", "rake", "test"]
