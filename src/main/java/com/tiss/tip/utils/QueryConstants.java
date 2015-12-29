package com.tiss.tip.utils;


import org.elasticsearch.common.collect.ImmutableMap;

public class QueryConstants {

	public static final String DATETIME = "dateTime";

	public static final String INCIDENT_INDEX = "incident";

	public static final String[] ALL_TYPES = { "MalwareIncident", "WebIncident", "MssqlIncident", "MysqlIncident",
			"NetworkLayerIncident", "SipIncident", "SshIncident" };

	public static final String MALWARE_TYPE = "MalwareIncident";

	public static final String WEB_TYPE = "WebIncident";

	public static final ImmutableMap<Object, Object> ES_TYPES = ImmutableMap.builder().put("malware", "MalwareIncident")
			.put("web", "WebIncident").put("mssql", "MssqlIncident").put("mysql", "MysqlIncident")
			.put("network", "NetworkLayerIncident").put("sip", "SipIncident").put("ssh", "SshIncident").build();

}
