package com.tiss.tip.utils;

public enum WebAttackCategories {
	SQL_INJECTION {
		public String toString() {
			return "Sql Injection";
		}
	},
	PROXY {
		public String toString() {
			return "Proxy Abuse";
		}
	},
	SPAM {
		public String toString() {
			return "Spam";
		}
	},
	LEAKAGE {
		public String toString() {
			return "Information and Source Code Leakage";
		}
	},
	COMMAND_INJECTION {
		public String toString() {
			return "System Command Injection";
		}
	},

	CSRF {
		public String toString() {
			return "Cross-Site Request Forgery";
		}
	},
	SESSION {
		public String toString() {
			return "Session Hijacking";
		}
	},
	PHP_INJECTION {
		public String toString() {
			return "PHP Injection";
		}
	},

	REQUEST_ANOMALY {
		public String toString() {
			return "Request Anomaly";
		}
	},

	LFI_RFI {
		public String toString() {
			return "Local/Remote File Inclusion";
		}
	},
	XSS {
		public String toString() {
			return "Cross-Site Scripting";
		}
	},

}
