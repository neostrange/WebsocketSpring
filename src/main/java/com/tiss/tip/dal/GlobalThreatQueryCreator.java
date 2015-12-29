package com.tiss.tip.dal;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.search.SearchType;
import org.elasticsearch.common.collect.ImmutableMap;
import org.elasticsearch.index.query.BoolFilterBuilder;
import org.elasticsearch.index.query.FilterBuilder;
import org.elasticsearch.index.query.FilterBuilders;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.aggregations.AggregationBuilders;
import org.elasticsearch.search.aggregations.bucket.filters.InternalFilters;
import org.elasticsearch.search.aggregations.bucket.terms.Terms;
import org.elasticsearch.search.sort.SortBuilders;
import org.elasticsearch.search.sort.SortOrder;
import org.elasticsearch.search.aggregations.bucket.filters.Filters.Bucket;
import org.elasticsearch.search.aggregations.bucket.nested.Nested;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.elasticsearch.core.ElasticsearchTemplate;
import org.springframework.data.elasticsearch.core.ResultsExtractor;
import org.springframework.data.elasticsearch.core.query.NativeSearchQueryBuilder;
import org.springframework.data.elasticsearch.core.query.SearchQuery;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tiss.tip.utils.QueryConstants;
import com.tiss.tip.utils.WebAttackCategories;

@Component
public class GlobalThreatQueryCreator {

	private static QueryBuilder query;

	private static SearchQuery searchQuery;

	@Autowired
	private ElasticsearchTemplate elasticsearchTemplate;

	private static final Logger logger = LoggerFactory.getLogger(GlobalThreatQueryCreator.class);

	public static final ImmutableMap<Object, Object> ES_TYPES = ImmutableMap.builder().put("malware", "MalwareIncident")
			.put("web", "WebIncident").put("mssql", "MssqlIncident").put("mysql", "MysqlIncident")
			.put("network", "NetworkLayerIncident").put("sip", "SipIncident").put("ssh", "SshIncident").build();

	public static HashMap<String, FilterBuilder> attackTypeFilter = new HashMap<String, FilterBuilder>();

	static {
		FilterBuilder ssh = FilterBuilders.termFilter("_type", "SshIncident");
		FilterBuilder application = FilterBuilders.boolFilter()
				.should(FilterBuilders.termFilter("_type", "SipIncident"))
				.should(FilterBuilders.termFilter("_type", "WebIncident"));
		FilterBuilder database = FilterBuilders.boolFilter().should(FilterBuilders.termFilter("_type", "MssqlIncident"))
				.should(FilterBuilders.termFilter("_type", "MysqlIncident"));
		FilterBuilder malware = FilterBuilders.boolFilter().should(FilterBuilders.termFilter("_type", "MssqlIncident"))
				.should(FilterBuilders.termFilter("_type", "MalwareIncident"));
		FilterBuilder sip = FilterBuilders.termFilter("_type", "SipIncident");
		FilterBuilder web = FilterBuilders.termFilter("_type", "WebIncident");
		attackTypeFilter.put("ssh", ssh);
		attackTypeFilter.put("application", application);
		attackTypeFilter.put("db", database);
		attackTypeFilter.put("sip", sip);
		attackTypeFilter.put("web", web);
		attackTypeFilter.put("malware", malware);
	}

	public static final String[] globalSummary = { "SSH Attacks", "Application Exploit Attempts", "Network Exploit",
			"Database Attacks", "Reconnaissance", "DOS Attacks", "Network Policy Violation", "Possible Compromise",
			"Malware Infection" };

	public static final String[] sshSummary = { "Total Attempts", "Successful Attacks", "Usernames", "Passwords",
			"Inputs" };

	public static final String[] dbSummary = { "Total Attempts", "Mssql Attacks", "Mysql Attacks" };

	// Extract IP and Lat/long
	public List<JsonNode> getIPsandGeoLocation(String countryCode, String to, String from, String category) {
		QueryBuilder country = QueryBuilders.matchQuery("origin.srcCountryCode", countryCode);
		BoolFilterBuilder filter = FilterBuilders.boolFilter();
		if (attackTypeFilter.containsKey(category)) {
			filter.must(attackTypeFilter.get(category));
			query = from == null && to == null ? QueryBuilders.filteredQuery(country, filter)
					: QueryBuilders.filteredQuery(country,
							filter.must(ESQueryCreator.createDateTimeRangeFilter(from, to)));

			searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
					.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(QueryConstants.ALL_TYPES)
					.addAggregation(AggregationBuilders.terms("IPs").field("srcIP").size(0)
							.subAggregation(AggregationBuilders.terms("lat").field("origin.geoPoint.lat")
									.showTermDocCountError(true))
							.subAggregation(AggregationBuilders.terms("long").field("origin.geoPoint.lon")
									.showTermDocCountError(true)))

					.build();

			return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

				@Override
				public List<JsonNode> extract(SearchResponse response) {
					Terms t = response.getAggregations().get("IPs");
					HashMap<String, Object> ips = new HashMap<String, Object>();
					List<JsonNode> ipGeo = new ArrayList<JsonNode>();
					Terms tmp = null;
					String ip = null;
					int i = 0;
					for (Terms.Bucket b : t.getBuckets()) {
						try {
							ip = InetAddress.getByName(b.getKey()).getHostAddress();
						} catch (UnknownHostException e) {
							logger.error("Error occurred while trying to convert from int [{}] to InetAddress",
									b.getKey(), e);
						}
						ips.put("ip", ip);
						ips.put("hits", b.getDocCount());
						tmp = b.getAggregations().get("lat");
						ips.put("lat", tmp.getBuckets().get(0).getKey());
						tmp = b.getAggregations().get("long");
						ips.put("long", tmp.getBuckets().get(0).getKey());
						ipGeo.add(new ObjectMapper().convertValue(ips, JsonNode.class));
					}
					return ipGeo;
				}
			});
		} else {
			logger.error("Attack Type [{}] is invalid", category);
			return null;
		}

	}
	
	/**
	 * 
	 * @param from
	 * @param to
	 * @param size
	 * @return
	 */
	public List<JsonNode> getGlobalAttacks(String from, String to, String countryCode) {

		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;
		query = from == null && to == null ? country
				: QueryBuilders.filteredQuery(country, ESQueryCreator.createDateTimeRangeFilter(from, to));

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(QueryConstants.ALL_TYPES)
				.addAggregation(AggregationBuilders.filters("GlobalAgg")
						.filter(globalSummary[0], FilterBuilders.termFilter("_type", "SshIncident"))
						.filter(globalSummary[1],
								FilterBuilders.boolFilter().should(FilterBuilders.termFilter("_type", "SipIncident"),
										FilterBuilders.termFilter("_type", "WebIncident")))
						.filter(globalSummary[2], FilterBuilders.termFilter("_type", "NetworkLayerIncident"))
						.filter(globalSummary[3],
								FilterBuilders.boolFilter().should(FilterBuilders.termFilter("_type", "MysqlIncident"),
										FilterBuilders.termFilter("_type", "MssqlIncident")))
						.filter(globalSummary[4],
								FilterBuilders.boolFilter()
										.should(FilterBuilders.queryFilter(QueryBuilders.wildcardQuery(
												"NetworkLayerIncident.signatureClass", "*attempted-recon*")),
								FilterBuilders.queryFilter(QueryBuilders
										.wildcardQuery("NetworkLayerIncident.signatureClass", "*misc-activity*")))
								.must(FilterBuilders.termFilter("_type", "NetworkLayerIncident")))
						.filter(globalSummary[5],
								FilterBuilders.boolFilter()
										.must(FilterBuilders.queryFilter(QueryBuilders.wildcardQuery(
												"NetworkLayerIncident.signatureClass", "*attempted-dos*"))))
						.filter(globalSummary[6],
								FilterBuilders.boolFilter()
										.must(FilterBuilders.queryFilter(QueryBuilders
												.wildcardQuery("NetworkLayerIncident.signatureClass", "*policy*"))))
						.filter(globalSummary[7],
								FilterBuilders.boolFilter()
										.must(FilterBuilders.queryFilter(QueryBuilders
												.wildcardQuery("NetworkLayerIncident.signatureClass", "*compromise*"))))
						.filter(globalSummary[8], FilterBuilders.termFilter("_type", "MalwareIncident")))

				.build();
		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {

				System.out.println(response.toString());
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				Map<String, Object> bucket = null;
				ObjectMapper myObjectMapper = new ObjectMapper();
				InternalFilters t = response.getAggregations().get("GlobalAgg");
				int i = 0;
				for (Bucket b : t.getBuckets()) {
					if (b.getDocCount() > 0) {
						bucket = new HashMap<String, Object>();
						bucket.put("category", globalSummary[i].toString());
						bucket.put("hits", String.valueOf(b.getDocCount()));
						jnode.add(myObjectMapper.convertValue(bucket, JsonNode.class));
					}
					i++;

				}

				return jnode;
			}
		});

	}

	public List<JsonNode> getGlobalSSH(String from, String to, String countryCode) {

		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;
		query = from == null && to == null ? country
				: QueryBuilders.filteredQuery(country, ESQueryCreator.createDateTimeRangeFilter(from, to));

		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes("SshIncident")
				.addAggregation(AggregationBuilders.filters("GlobalSsh")
						.filter(sshSummary[0], FilterBuilders.termFilter("_type", "SshIncident")).filter(sshSummary[1],
								FilterBuilders.boolFilter().should(FilterBuilders.termFilter("inputList.success", true),
										FilterBuilders.nestedFilter("authList",
												FilterBuilders.termFilter("authList.success", true)))))
				.addAggregation(AggregationBuilders.nested("UsernamesUsed").path("authList")
						.subAggregation(AggregationBuilders.terms("Usernames").field("authList.username")))
				.addAggregation(AggregationBuilders.nested("PasswordsUsed").path("authList")
						.subAggregation(AggregationBuilders.terms("Passwords").field("authList.password")))
				.addAggregation(AggregationBuilders.nested("Inputs").path("authList")
						.subAggregation(AggregationBuilders.terms("In").field("inputList.command")))

				.build();

		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {

				System.out.println(response.toString());
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				List<JsonNode> subNode = new ArrayList<JsonNode>();
				Map<String, Object> bucket = null;
				ObjectMapper myObjectMapper = new ObjectMapper();
				InternalFilters t = response.getAggregations().get("GlobalSsh");
				int i = 0;
				for (Bucket b : t.getBuckets()) {
					if (b.getDocCount() > 0) {
						bucket = new HashMap<String, Object>();
						bucket.put("category", sshSummary[i].toString());
						bucket.put("hits", String.valueOf(b.getDocCount()));
						jnode.add(myObjectMapper.convertValue(bucket, JsonNode.class));
					}
					i++;

				}

				// Get Usernames
				Nested nest = response.getAggregations().get("UsernamesUsed");
				Terms terms = nest.getAggregations().get("Usernames");
				for (Terms.Bucket b : terms.getBuckets()) {
					bucket = new HashMap<String, Object>();
					bucket.put("username", b.getKey());
					bucket.put("hits", b.getDocCount());
					subNode.add(myObjectMapper.convertValue(bucket, JsonNode.class));
				}
				bucket = new HashMap<String, Object>();
				bucket.put("usernames", subNode);
				bucket.put("hits", nest.getDocCount());
				jnode.add(myObjectMapper.convertValue(bucket, JsonNode.class));

				// Get Passwords
				nest = response.getAggregations().get("PasswordsUsed");
				subNode = new ArrayList<JsonNode>();
				terms = nest.getAggregations().get("Passwords");
				for (Terms.Bucket b : terms.getBuckets()) {
					bucket = new HashMap<String, Object>();
					bucket.put("password", b.getKey());
					bucket.put("hits", b.getDocCount());
					subNode.add(myObjectMapper.convertValue(bucket, JsonNode.class));
				}
				bucket = new HashMap<String, Object>();
				bucket.put("passwords", subNode);
				bucket.put("hits", nest.getDocCount());
				jnode.add(myObjectMapper.convertValue(bucket, JsonNode.class));

				// Inputs
				nest = response.getAggregations().get("Inputs");
				terms = nest.getAggregations().get("In");
				bucket = new HashMap<String, Object>();
				bucket.put("inputs", nest.getDocCount());
				jnode.add(myObjectMapper.convertValue(bucket, JsonNode.class));

				return jnode;
			}
		});
	}

	public List<JsonNode> getGlobalDatabase(String from, String to, String countryCode) {

		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;
		query = from == null && to == null ? country
				: QueryBuilders.filteredQuery(country, ESQueryCreator.createDateTimeRangeFilter(from, to));

		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes("MssqlIncident", "MysqlIncident")
				.addAggregation(AggregationBuilders.filters("GlobalDb")
						.filter("Mssql", FilterBuilders.termFilter("_type", "MssqlIncident"))
						.filter("Mysql", FilterBuilders.termFilter("_type", "MysqlIncident")))
				.build();

		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {

				System.out.println(response.toString());
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				Map<String, Object> bucket = null;
				ObjectMapper myObjectMapper = new ObjectMapper();
				InternalFilters t = response.getAggregations().get("GlobalDb");
				int i = 1;
				long sum = 0;
				for (Bucket b : t.getBuckets()) {
					if (b.getDocCount() > 0) {
						bucket = new HashMap<String, Object>();
						bucket.put("category", dbSummary[i].toString());
						sum += b.getDocCount();
						bucket.put("hits", String.valueOf(b.getDocCount()));
						jnode.add(myObjectMapper.convertValue(bucket, JsonNode.class));
					}
					i++;

				}
				bucket = new HashMap<String, Object>();
				bucket.put("category", dbSummary[0]);
				bucket.put("hits", sum);
				jnode.add(myObjectMapper.convertValue(bucket, JsonNode.class));


				return jnode;
			}
		});
	}

	public List<JsonNode> getGlobalMalware(String from, String to, String countryCode) {

		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;
		query = from == null && to == null ? country
				: QueryBuilders.filteredQuery(country, ESQueryCreator.createDateTimeRangeFilter(from, to));

		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes("MalwareIncident")
				.addAggregation(AggregationBuilders.terms("Malwares").field("vtScan.VTscanResults.Kaspersky"))
				.build();

		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {

				System.out.println(response.toString());
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				Map<String, Object> bucket = null;
				ObjectMapper myObjectMapper = new ObjectMapper();
				Terms t = response.getAggregations().get("Malwares");
				for (Terms.Bucket b : t.getBuckets()) {
					if (b.getDocCount() > 0) {
						bucket = new HashMap<String, Object>();
						bucket.put("malware", b.getKey());
						bucket.put("hits", b.getDocCount());
						jnode.add(myObjectMapper.convertValue(bucket, JsonNode.class));
					}

				}

				return jnode;
			}
		});
	}

	public List<JsonNode> getGlobalSip(String from, String to, String countryCode) {

		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;
		query = from == null && to == null ? country
				: QueryBuilders.filteredQuery(country, ESQueryCreator.createDateTimeRangeFilter(from, to));

		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes("SipIncident")
				.addAggregation(AggregationBuilders.terms("SipAttacks").field("_type"))
				.addAggregation(AggregationBuilders.terms("SipMethod").field("sipMethod"))
				.build();

		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {

				System.out.println(response.toString());
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				Map<String, Object> bucket = new HashMap<String, Object>();
				ObjectMapper myObjectMapper = new ObjectMapper();
				Terms t = response.getAggregations().get("SipAttacks");
				bucket.put("Sip Attacks", t.getBucketByKey("SipIncident").getDocCount());
				jnode.add(myObjectMapper.convertValue(bucket, JsonNode.class));
				t = response.getAggregations().get("SipMethod");
				for (Terms.Bucket b : t.getBuckets()) {
					if (b.getDocCount() > 0) {
						bucket = new HashMap<String, Object>();
						if (b.getKey().equalsIgnoreCase("ACK")) {

							bucket.put("category", "Ack Flooding");
						} else if (b.getKey().equalsIgnoreCase("REGISTER")) {

							bucket.put("category", "Registrar Flooding");
						} else if (b.getKey().equalsIgnoreCase("OPTIONS")) {

							bucket.put("category", "Option Flooding");
						}

						bucket.put("hits", b.getDocCount());
						jnode.add(myObjectMapper.convertValue(bucket, JsonNode.class));
					}

				}


				return jnode;
			}
		});
	}

	public List<JsonNode> getGlobalWeb(String from, String to, String countryCode) {

		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;
		query = from == null && to == null ? country
				: QueryBuilders.filteredQuery(country, ESQueryCreator.createDateTimeRangeFilter(from, to));

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(
						QueryConstants.INCIDENT_INDEX)
				.withTypes(
						(String) ES_TYPES
								.get("web"))
				.addAggregation(
						AggregationBuilders.filters("TopWebAttacks")
								.filter(WebAttackCategories.SQL_INJECTION.toString(),
										FilterBuilders.queryFilter(QueryBuilders.wildcardQuery("rulesList.ruleMessage",
												"*SQL*Injection*")))
								.filter(WebAttackCategories.PROXY.toString(),
										FilterBuilders.queryFilter(
												QueryBuilders.wildcardQuery("rulesList.ruleMessage", "*Proxy*")))
								.filter(WebAttackCategories.SPAM.toString(),
										FilterBuilders.queryFilter(
												QueryBuilders.wildcardQuery("rulesList.ruleMessage", "*SPAM*")))
								.filter(WebAttackCategories.LEAKAGE.toString(),
										FilterBuilders.queryFilter(
												QueryBuilders.wildcardQuery("rulesList.ruleMessage", "*eakage*")))
								.filter(WebAttackCategories.COMMAND_INJECTION.toString(),
										FilterBuilders.queryFilter(QueryBuilders.wildcardQuery("rulesList.ruleMessage",
												"*Command*Injection*")))
								.filter(WebAttackCategories.CSRF.toString(),
										FilterBuilders.queryFilter(
												QueryBuilders.wildcardQuery("rulesList.ruleMessage", "*CSRF*")))
								.filter(WebAttackCategories.SESSION.toString(),
										FilterBuilders.queryFilter(
												QueryBuilders.wildcardQuery("rulesList.ruleMessage", "*Session*")))
								.filter(WebAttackCategories.PHP_INJECTION.toString(),
										FilterBuilders.queryFilter(QueryBuilders.wildcardQuery("rulesList.ruleMessage",
												"*PHP*Injection*")))
								.filter(WebAttackCategories.REQUEST_ANOMALY.toString(),
										FilterBuilders.orFilter(
												FilterBuilders.queryFilter(QueryBuilders
														.wildcardQuery("rulesList.ruleMessage", "*equest*")),
										FilterBuilders.queryFilter(QueryBuilders.wildcardQuery("rulesList.ruleMessage",
												"*Inbound*Anomaly*")),
										FilterBuilders.queryFilter(
												QueryBuilders.wildcardQuery("rulesList.ruleMessage", "*Header*"))))
								.filter(WebAttackCategories.LFI_RFI.toString(),
										FilterBuilders.queryFilter(
												QueryBuilders.wildcardQuery("rulesList.ruleMessage", "*Inclusion*")))
								.filter(WebAttackCategories.XSS.toString(),
										FilterBuilders.queryFilter(
												QueryBuilders.wildcardQuery("rulesList.ruleMessage", "*XSS*"))))
				.build();
		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {

				List<JsonNode> jnode = new ArrayList<JsonNode>();
				Map<String, Object> bucket = null;
				ObjectMapper myObjectMapper = new ObjectMapper();
				InternalFilters t = response.getAggregations().get("TopWebAttacks");
				WebAttackCategories[] cat = WebAttackCategories.values();
				int i = 0;
				for (Bucket b : t.getBuckets()) {
					if (b.getDocCount() > 0) {
						bucket = new HashMap<String, Object>();
						bucket.put("attack", cat[i].toString());
						bucket.put("hits", b.getDocCount());
						jnode.add(myObjectMapper.convertValue(bucket, JsonNode.class));
					}
					i++;

				}
				return jnode;
			}
		});

	}

	public List<JsonNode> getGlobalApplication(String from, String to, String countryCode) {

		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;
		query = from == null && to == null ? country
				: QueryBuilders.filteredQuery(country, ESQueryCreator.createDateTimeRangeFilter(from, to));

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(
						QueryConstants.INCIDENT_INDEX)
				.withTypes(
						(String) ES_TYPES
								.get("web"))
				.addAggregation(
						AggregationBuilders.filters("TopWebAttacks")
								.filter(WebAttackCategories.SQL_INJECTION.toString(),
										FilterBuilders.queryFilter(QueryBuilders.wildcardQuery("rulesList.ruleMessage",
												"*SQL*Injection*")))
								.filter(WebAttackCategories.PROXY.toString(),
										FilterBuilders.queryFilter(
												QueryBuilders.wildcardQuery("rulesList.ruleMessage", "*Proxy*")))
								.filter(WebAttackCategories.SPAM.toString(),
										FilterBuilders.queryFilter(
												QueryBuilders.wildcardQuery("rulesList.ruleMessage", "*SPAM*")))
								.filter(WebAttackCategories.LEAKAGE.toString(),
										FilterBuilders.queryFilter(
												QueryBuilders.wildcardQuery("rulesList.ruleMessage", "*eakage*")))
								.filter(WebAttackCategories.COMMAND_INJECTION.toString(),
										FilterBuilders.queryFilter(QueryBuilders.wildcardQuery("rulesList.ruleMessage",
												"*Command*Injection*")))
								.filter(WebAttackCategories.CSRF.toString(),
										FilterBuilders.queryFilter(
												QueryBuilders.wildcardQuery("rulesList.ruleMessage", "*CSRF*")))
								.filter(WebAttackCategories.SESSION.toString(),
										FilterBuilders.queryFilter(
												QueryBuilders.wildcardQuery("rulesList.ruleMessage", "*Session*")))
								.filter(WebAttackCategories.PHP_INJECTION.toString(),
										FilterBuilders.queryFilter(QueryBuilders.wildcardQuery("rulesList.ruleMessage",
												"*PHP*Injection*")))
								.filter(WebAttackCategories.REQUEST_ANOMALY.toString(),
										FilterBuilders.orFilter(
												FilterBuilders.queryFilter(QueryBuilders
														.wildcardQuery("rulesList.ruleMessage", "*equest*")),
										FilterBuilders.queryFilter(QueryBuilders.wildcardQuery("rulesList.ruleMessage",
												"*Inbound*Anomaly*")),
										FilterBuilders.queryFilter(
												QueryBuilders.wildcardQuery("rulesList.ruleMessage", "*Header*"))))
								.filter(WebAttackCategories.LFI_RFI.toString(),
										FilterBuilders.queryFilter(
												QueryBuilders.wildcardQuery("rulesList.ruleMessage", "*Inclusion*")))
								.filter(WebAttackCategories.XSS.toString(),
										FilterBuilders.queryFilter(
												QueryBuilders.wildcardQuery("rulesList.ruleMessage", "*XSS*"))))

				.build();
		List<JsonNode> list = elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {

				List<JsonNode> jnode = new ArrayList<JsonNode>();
				Map<String, Object> bucket = null;
				ObjectMapper myObjectMapper = new ObjectMapper();
				InternalFilters t = response.getAggregations().get("TopWebAttacks");
				WebAttackCategories[] cat = WebAttackCategories.values();
				int i = 0;
				for (Bucket b : t.getBuckets()) {
					if (b.getDocCount() > 0) {
						bucket = new HashMap<String, Object>();
						bucket.put("attack", cat[i].toString());
						bucket.put("hits", b.getDocCount());
						jnode.add(myObjectMapper.convertValue(bucket, JsonNode.class));
					}
					i++;

				}

				return jnode;
			}
		});

		list.addAll(getGlobalSip(from, to, countryCode));
		return list;
	}

	public JsonNode getIPAnalysis(String from, String to, String ip) {

		JsonNode ipNode = null;
		final HashMap<String, Object> map = new HashMap<String, Object>();
		QueryBuilder ipQuery = QueryBuilders.matchQuery("srcIP", ip);

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(ipQuery).withSearchType(SearchType.QUERY_AND_FETCH)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(QueryConstants.ALL_TYPES)
				.withSort(SortBuilders.fieldSort("dateTime").order(SortOrder.ASC)).build();
		JsonNode n = elasticsearchTemplate.query(searchQuery, new ResultsExtractor<JsonNode>() {

			@Override
			public JsonNode extract(SearchResponse response) {
				if (response.getHits() != null) {
					SearchHit hit = response.getHits().getAt(0);
					map.put("firstSeen", hit.getSource().get("dateTime"));
					map.put("origin", hit.getSource().get("origin"));
					map.put("Total Attacks", response.getHits().getTotalHits());
				}
				return new ObjectMapper().convertValue(map, JsonNode.class);

			}
		});

		searchQuery = new NativeSearchQueryBuilder().withQuery(ipQuery).withSearchType(SearchType.QUERY_AND_FETCH)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(QueryConstants.ALL_TYPES)
				.withSort(SortBuilders.fieldSort("dateTime").order(SortOrder.DESC)).build();
		n = elasticsearchTemplate.query(searchQuery, new ResultsExtractor<JsonNode>() {

			@Override
			public JsonNode extract(SearchResponse response) {

				if (response.getHits() != null) {
					SearchHit hit = response.getHits().getAt(0);
					map.put("lastSeen", hit.getSource().get("dateTime"));
				}
				return null;

			}
		});

		FilterBuilder filter = FilterBuilders.boolFilter()
				.should(FilterBuilders.termFilter("signatureClass", "attempted-recon"))
				.should(FilterBuilders.termFilter("signatureClass", "misc-activity"));

		query = from == null && to == null ? QueryBuilders.filteredQuery(ipQuery, filter)
				: QueryBuilders.filteredQuery(ipQuery, FilterBuilders.boolFilter().should(filter)
						.must(ESQueryCreator.createDateTimeRangeFilter(from, to), filter));
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(QueryConstants.ALL_TYPES).build();

		long t = elasticsearchTemplate.count(searchQuery);
		map.put("Probing Attempts", t);

		ipNode = new ObjectMapper().convertValue(map, JsonNode.class);
		return ipNode;
	}
}
