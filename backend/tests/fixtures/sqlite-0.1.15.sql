-- The SQLite schema of Cobe News 0.1.15 (sqlite3 .schema of a live database, no data) – tests/test_sqlite_import.py
CREATE TABLE news_sources (
	id CHAR(32) NOT NULL, 
	"key" VARCHAR(64) NOT NULL, 
	name VARCHAR(100) NOT NULL, 
	url VARCHAR(500) NOT NULL, 
	site VARCHAR(300) NOT NULL, 
	builtin BOOLEAN NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	etag VARCHAR(300), 
	last_modified VARCHAR(100), 
	last_fetch_at DATETIME, 
	last_ok_at DATETIME, 
	next_fetch_at DATETIME, 
	failures INTEGER NOT NULL, 
	error VARCHAR(200), 
	logo BLOB, 
	logo_type VARCHAR(40), 
	logo_checked_at DATETIME, 
	created_at DATETIME NOT NULL, switched_at DATETIME, primed_at DATETIME, 
	PRIMARY KEY (id), 
	UNIQUE ("key")
);
CREATE TABLE users (
	id CHAR(32) NOT NULL, 
	username VARCHAR(128) NOT NULL, 
	display_name VARCHAR(255) NOT NULL, 
	email VARCHAR(255), 
	role VARCHAR(16) NOT NULL, 
	auth_source VARCHAR(8) NOT NULL, 
	external_id VARCHAR(255), 
	password_hash VARCHAR(255), 
	must_change_password BOOLEAN NOT NULL, 
	totp_secret_enc TEXT, 
	totp_last_step INTEGER, 
	is_active BOOLEAN NOT NULL, 
	deactivated_reason VARCHAR(32), 
	is_emergency BOOLEAN NOT NULL, 
	desktop JSON NOT NULL, 
	created_at DATETIME NOT NULL, 
	last_login_at DATETIME, 
	last_login_ip VARCHAR(64), version INTEGER NOT NULL DEFAULT 1, 
	PRIMARY KEY (id), 
	UNIQUE (username)
);
CREATE TABLE group_mappings (
	id CHAR(32) NOT NULL, 
	source VARCHAR(8) NOT NULL, 
	group_id VARCHAR(500) NOT NULL, 
	group_name VARCHAR(255) NOT NULL, 
	role VARCHAR(16) NOT NULL, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE notify_rules (
	id CHAR(32) NOT NULL, 
	name VARCHAR(100) NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	severities JSON NOT NULL, 
	sources JSON NOT NULL, 
	lang VARCHAR(2) NOT NULL, 
	created_at DATETIME NOT NULL, 
	active_since DATETIME NOT NULL, kinds JSON NOT NULL DEFAULT '["news"]', earlier JSON NOT NULL DEFAULT '[]', version INTEGER NOT NULL DEFAULT 1, 
	PRIMARY KEY (id)
);
CREATE TABLE settings (
	"key" VARCHAR(64) NOT NULL, 
	value JSON NOT NULL, 
	PRIMARY KEY ("key")
);
CREATE TABLE news_items (
	id CHAR(32) NOT NULL, 
	source_id CHAR(32) NOT NULL, 
	url VARCHAR(2000) NOT NULL, 
	url_key VARCHAR(64) NOT NULL, 
	title VARCHAR(500) NOT NULL, 
	title_key VARCHAR(64) NOT NULL, 
	summary TEXT NOT NULL, 
	content_html TEXT NOT NULL, 
	published_at DATETIME NOT NULL, 
	fetched_at DATETIME NOT NULL, 
	severity VARCHAR(10) NOT NULL, 
	reasons JSON NOT NULL, 
	cves JSON NOT NULL, 
	also_in JSON NOT NULL, search TEXT NOT NULL DEFAULT '', seq INTEGER, seen_at DATETIME, backlog BOOLEAN NOT NULL DEFAULT 0, 
	PRIMARY KEY (id), 
	FOREIGN KEY(source_id) REFERENCES news_sources (id) ON DELETE CASCADE, 
	UNIQUE (url_key)
);
CREATE TABLE user_sessions (
	id CHAR(32) NOT NULL, 
	token_hash VARCHAR(64) NOT NULL, 
	user_id CHAR(32) NOT NULL, 
	stage VARCHAR(16) NOT NULL, 
	created_at DATETIME NOT NULL, 
	last_seen_at DATETIME NOT NULL, 
	expires_at DATETIME NOT NULL, 
	ip VARCHAR(64), 
	user_agent VARCHAR(255), 
	pending JSON NOT NULL, reauth_at DATETIME, 
	PRIMARY KEY (id), 
	UNIQUE (token_hash), 
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE TABLE news_reads (
	user_id CHAR(32) NOT NULL, 
	item_id CHAR(32) NOT NULL, 
	read_at DATETIME NOT NULL, 
	PRIMARY KEY (user_id, item_id), 
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE, 
	FOREIGN KEY(item_id) REFERENCES news_items (id) ON DELETE CASCADE
);
CREATE TABLE notify_channels (
	id CHAR(32) NOT NULL, 
	name VARCHAR(100) NOT NULL, 
	type VARCHAR(10) NOT NULL, 
	config JSON NOT NULL, 
	secrets JSON NOT NULL, 
	target VARCHAR(300), 
	created_at DATETIME NOT NULL, 
	last_sent_at DATETIME, 
	last_error VARCHAR(200), 
	last_error_at DATETIME, 
	failures INTEGER NOT NULL, 
	next_try_at DATETIME, version INTEGER NOT NULL DEFAULT 1, 
	PRIMARY KEY (id)
);
CREATE TABLE notify_rule_channels (
	rule_id CHAR(32) NOT NULL, 
	channel_id CHAR(32) NOT NULL, 
	added_at DATETIME NOT NULL, 
	PRIMARY KEY (rule_id, channel_id), 
	FOREIGN KEY(rule_id) REFERENCES notify_rules (id) ON DELETE CASCADE, 
	FOREIGN KEY(channel_id) REFERENCES notify_channels (id) ON DELETE CASCADE
);
CREATE TABLE notify_deliveries (
	channel_id CHAR(32) NOT NULL, 
	item_id CHAR(32) NOT NULL, 
	rule_id CHAR(32), 
	sent_at DATETIME NOT NULL, 
	PRIMARY KEY (channel_id, item_id), 
	FOREIGN KEY(channel_id) REFERENCES notify_channels (id) ON DELETE CASCADE, 
	FOREIGN KEY(item_id) REFERENCES news_items (id) ON DELETE CASCADE
);
CREATE TABLE counters (
	name VARCHAR(32) NOT NULL, 
	value INTEGER NOT NULL, 
	PRIMARY KEY (name)
);
CREATE TABLE push_subscriptions (
	id CHAR(32) NOT NULL, 
	user_id CHAR(32) NOT NULL, 
	endpoint VARCHAR(1000) NOT NULL, 
	p256dh VARCHAR(200) NOT NULL, 
	auth VARCHAR(64) NOT NULL, 
	lang VARCHAR(2) NOT NULL, 
	label VARCHAR(100) NOT NULL, 
	cursor INTEGER NOT NULL, 
	created_at DATETIME NOT NULL, 
	last_ok_at DATETIME, 
	last_error VARCHAR(200), 
	last_error_at DATETIME, 
	failures INTEGER NOT NULL, 
	next_try_at DATETIME, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE, 
	UNIQUE (endpoint)
);
CREATE TABLE vendor_follows (
	id CHAR(32) NOT NULL, 
	product VARCHAR(80) NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	note VARCHAR(500) NOT NULL, 
	tags JSON NOT NULL, 
	custom JSON, 
	created_at DATETIME NOT NULL, 
	updated_at DATETIME NOT NULL, 
	baseline_at DATETIME, 
	PRIMARY KEY (id), 
	UNIQUE (product)
);
CREATE TABLE vendor_advisories (
	id VARCHAR(120) NOT NULL, 
	source VARCHAR(16) NOT NULL, 
	ident VARCHAR(100) NOT NULL, 
	title VARCHAR(500) NOT NULL, 
	summary TEXT NOT NULL, 
	url VARCHAR(500) NOT NULL, 
	cves JSON NOT NULL, 
	cvss DOUBLE, 
	severity VARCHAR(10) NOT NULL, 
	exploited BOOLEAN NOT NULL, 
	published_at DATETIME, 
	updated_at DATETIME, 
	fetched_at DATETIME NOT NULL, 
	data JSON NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE vendor_fetch (
	"key" VARCHAR(300) NOT NULL, 
	etag VARCHAR(300), 
	last_modified VARCHAR(100), 
	cursor VARCHAR(100), 
	last_fetch_at DATETIME, 
	last_ok_at DATETIME, 
	next_fetch_at DATETIME, 
	failures INTEGER NOT NULL, 
	error VARCHAR(200), 
	items INTEGER NOT NULL, full_at DATETIME, 
	PRIMARY KEY ("key")
);
CREATE TABLE vendor_kev (
	cve VARCHAR(32) NOT NULL, 
	vendor VARCHAR(100) NOT NULL, 
	product VARCHAR(150) NOT NULL, 
	name VARCHAR(300) NOT NULL, 
	date_added VARCHAR(10) NOT NULL, 
	due VARCHAR(10) NOT NULL, 
	ransomware BOOLEAN NOT NULL, 
	PRIMARY KEY (cve)
);
CREATE TABLE vendor_events (
	id CHAR(32) NOT NULL, 
	"key" VARCHAR(400) NOT NULL, 
	kind VARCHAR(10) NOT NULL, 
	product VARCHAR(80) NOT NULL, 
	severity VARCHAR(10) NOT NULL, 
	data JSON NOT NULL, 
	baseline BOOLEAN NOT NULL, 
	created_at DATETIME NOT NULL, scope VARCHAR(400), 
	PRIMARY KEY (id), 
	UNIQUE ("key")
);
CREATE TABLE vendor_versions (
	id CHAR(32) NOT NULL, 
	follow_id CHAR(32) NOT NULL, 
	version VARCHAR(64) NOT NULL, 
	label VARCHAR(100) NOT NULL, 
	count INTEGER, 
	created_at DATETIME NOT NULL, 
	updated_at DATETIME NOT NULL, 
	baseline_at DATETIME, 
	PRIMARY KEY (id), 
	FOREIGN KEY(follow_id) REFERENCES vendor_follows (id) ON DELETE CASCADE
);
CREATE TABLE vendor_advisory_products (
	product VARCHAR(80) NOT NULL, 
	advisory_id VARCHAR(120) NOT NULL, 
	PRIMARY KEY (product, advisory_id), 
	FOREIGN KEY(advisory_id) REFERENCES vendor_advisories (id) ON DELETE CASCADE
);
CREATE TABLE vendor_deliveries (
	channel_id CHAR(32) NOT NULL, 
	event_id CHAR(32) NOT NULL, 
	rule_id CHAR(32), 
	sent_at DATETIME NOT NULL, 
	PRIMARY KEY (channel_id, event_id), 
	FOREIGN KEY(channel_id) REFERENCES notify_channels (id) ON DELETE CASCADE, 
	FOREIGN KEY(event_id) REFERENCES vendor_events (id) ON DELETE CASCADE
);
CREATE TABLE story_details (
	item_id CHAR(32) NOT NULL, 
	kind VARCHAR(12) NOT NULL, 
	ident VARCHAR(120) NOT NULL, 
	status VARCHAR(10) NOT NULL, 
	data JSON, 
	fetched_at DATETIME, 
	next_try_at DATETIME, 
	failures INTEGER NOT NULL, 
	error VARCHAR(200), 
	PRIMARY KEY (item_id), 
	FOREIGN KEY(item_id) REFERENCES news_items (id) ON DELETE CASCADE
);
CREATE TABLE news_item_sources (
	item_id CHAR(32) NOT NULL, 
	source_id CHAR(32) NOT NULL, 
	PRIMARY KEY (item_id, source_id), 
	FOREIGN KEY(item_id) REFERENCES news_items (id) ON DELETE CASCADE, 
	FOREIGN KEY(source_id) REFERENCES news_sources (id) ON DELETE CASCADE
);
CREATE INDEX ix_users_source_external ON users (auth_source, external_id);
CREATE UNIQUE INDEX ux_group_mappings ON group_mappings (source, group_id);
CREATE INDEX ix_news_items_title_key ON news_items (title_key);
CREATE INDEX ix_news_items_published ON news_items (published_at, id);
CREATE INDEX ix_user_sessions_user_id ON user_sessions (user_id);
CREATE INDEX ix_news_reads_item_id ON news_reads (item_id);
CREATE INDEX ix_news_items_fetched ON news_items (fetched_at);
CREATE INDEX ix_news_reads_user_read ON news_reads (user_id, read_at);
CREATE INDEX ix_notify_rule_channels_channel_id ON notify_rule_channels (channel_id);
CREATE INDEX ix_notify_deliveries_item_id ON notify_deliveries (item_id);
CREATE INDEX ix_push_subscriptions_user_id ON push_subscriptions (user_id);
CREATE INDEX ix_news_items_seq ON news_items (seq);
CREATE INDEX ix_vendor_advisories_published ON vendor_advisories (published_at);
CREATE INDEX ix_vendor_events_created ON vendor_events (created_at);
CREATE INDEX ix_vendor_versions_follow_id ON vendor_versions (follow_id);
CREATE INDEX ix_vendor_advisory_products_advisory_id ON vendor_advisory_products (advisory_id);
CREATE INDEX ix_vendor_deliveries_event_id ON vendor_deliveries (event_id);
CREATE INDEX ix_news_item_sources_source_id ON news_item_sources (source_id);
CREATE INDEX ix_news_items_source ON news_items (source_id, id);
CREATE INDEX ix_vendor_events_scope ON vendor_events (scope);
