package com.tiss.tip.dal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.search.SearchType;
import org.elasticsearch.index.query.FilterBuilder;
import org.elasticsearch.index.query.FilterBuilders;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.aggregations.AggregationBuilders;
import org.elasticsearch.search.aggregations.bucket.filters.Filters;
import org.elasticsearch.search.aggregations.bucket.filters.InternalFilters;
import org.elasticsearch.search.aggregations.bucket.histogram.DateHistogram;
import org.elasticsearch.search.aggregations.bucket.histogram.DateHistogram.Bucket;
import org.elasticsearch.search.aggregations.bucket.histogram.DateHistogram.Interval;
import org.elasticsearch.search.aggregations.bucket.histogram.DateHistogramBuilder;
import org.elasticsearch.search.aggregations.bucket.histogram.Histogram;
import org.elasticsearch.search.sort.SortBuilders;
import org.elasticsearch.search.sort.SortOrder;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.elasticsearch.core.ElasticsearchTemplate;
import org.springframework.data.elasticsearch.core.ResultsExtractor;
import org.springframework.data.elasticsearch.core.query.NativeSearchQueryBuilder;
import org.springframework.data.elasticsearch.core.query.SearchQuery;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tiss.tip.utils.QueryConstants;

@Component
public class IPQueryCreator {

	private static QueryBuilder query;

	private static SearchQuery searchQuery;

	@Autowired
	private ElasticsearchTemplate elasticsearchTemplate;

	public static final String[] attackCategories = { "SSH Attacks", "SIP Attacks", "Web Attacks", "Database Attacks",
			"Reconnaissance", "Malware Infection", "Total Attacks" };

	private static final Logger logger = LoggerFactory.getLogger(IPQueryCreator.class);

	/**
	 * 
	 * @param from
	 * @param to
	 * @param ip
	 * @param size
	 * @return
	 */
	public List<JsonNode> getIPHistory(String from, String to, String ip, int size) {
		logger.info("Starting getIPHistory");

		QueryBuilder ipQuery = QueryBuilders.matchQuery("srcIP", ip);

		query = from == null && to == null ? ipQuery
				: QueryBuilders.filteredQuery(ipQuery, ESQueryCreator.createDateTimeRangeFilter(from, to));
		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.QUERY_AND_FETCH)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(QueryConstants.ALL_TYPES)
				.withSort(SortBuilders.fieldSort("dateTime").order(SortOrder.DESC))
				.withPageable(new PageRequest(0, size)).build();
		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			public List<JsonNode> extract(SearchResponse response) {
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				HashMap<String, Object> event;
				HashMap<String, Object> attackCat;
				if (response.getHits() != null) {
					SearchHit[] hits = response.getHits().hits();
					Map<String, Object> tempSource;
					for (SearchHit h : hits) {
						event = new HashMap<String, Object>();
						attackCat = new HashMap<String, Object>();
						event.put("dateTime", h.getSource().get("dateTime"));
						tempSource = h.getSource();
						// for network
						if (tempSource.containsKey("signature")) {
							event.put("attackType", "Network Layer Attack");
							attackCat.put("attackSignature", tempSource.get("signature"));
							attackCat.put("attackClass", tempSource.get("signatureClass"));
							event.put("attackDetails", attackCat);
						} else if (tempSource.containsKey("md5Hash")) {
							event.put("attackType", "Malware Downloaded");
							attackCat.put("Malware Hash", tempSource.get("md5Hash"));
							if (tempSource.containsKey("vtScan")) {
								JsonNode m = new ObjectMapper().convertValue(tempSource.get("vtScan"), JsonNode.class);
								attackCat.put("Malware Name",
										m.get("Kaspersky") == null ? "unknown" : m.get("Kaspersky"));
							}
							event.put("attackDetails", attackCat);
						}
						// SSH
						else if (tempSource.containsKey("sessionId")) {
							event.put("attackType", "SSH Brute Force Attack");
							JsonNode m = null;
							if (tempSource.containsKey("authList")) {
								m = new ObjectMapper().convertValue(tempSource.get("authList"), JsonNode.class);
								attackCat.put("authAttempts", m);
							}

							if (tempSource.containsKey("inputList")) {
								m = new ObjectMapper().convertValue(tempSource.get("inputList"), JsonNode.class);
								attackCat.put("inputs", m);
							}
							event.put("attackDetails", attackCat);

						}

						else if (tempSource.containsKey("sipAgent")) {
							event.put("attackType", "SIP Attack");
							String method = (String) tempSource.get("sipMethod");
							if (method.equals("OPTIONS")) {
								attackCat.put("attackCategory", "Options Flooding");
							} else if (method.equals("REGISTER")) {
								attackCat.put("attackCategory", "Registry Flooding");
							} else if (method.equals("ACK")) {
								attackCat.put("attackCategory", "ACK Flooding");
							} else {
								attackCat.put("attackCategory", "Proxy Flooding");
							}
							event.put("attackDetails", attackCat);
						}

						// Mysql
						else if (tempSource.containsKey("mysqlCommands")) {
							event.put("attackType", "MySQL Attack");
							JsonNode j = null;
							if (tempSource.containsKey("mysqlCommands")) {
								j = new ObjectMapper().convertValue(tempSource.get("mysqlCommands"), JsonNode.class);
							}
							event.put("attackDetails", j);
						}

						// Mssql
						else if (tempSource.containsKey("mssqlClientName")) {
							event.put("attackType", "MSSQL Attack");
							event.put("attackDetails", tempSource.get("mssqlClientName"));
						}

						// Web
						else {
							event.put("attackType", "Web Attack");
							event.put("attackType", "MSSQL Attack");
							JsonNode j = null;
							if (tempSource.containsKey("ruleList")) {
								j = new ObjectMapper().convertValue(tempSource.get("ruleList"), JsonNode.class);
							}
							event.put("attackDetails", j);
						}

						jnode.add(new ObjectMapper().convertValue(event, JsonNode.class));

					}

				}

				return jnode;

			}

		});

	}

	/**
	 * 
	 * @param from
	 * @param to
	 * @param ip
	 * @param size
	 * @return
	 */
	public JsonNode getIPGeoInfo(String ip) {

		QueryBuilder ipQuery = QueryBuilders.matchQuery("srcIP", ip);
		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(ipQuery).withSearchType(SearchType.QUERY_AND_FETCH)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(QueryConstants.ALL_TYPES)
				.withPageable(new PageRequest(0, 1)).build();
		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<JsonNode>() {

			@Override
			public JsonNode extract(SearchResponse response) {
				System.out.println(response.toString());
				if (response.getHits() != null) {
					SearchHit hit = response.getHits().hits().length > 0 ? response.getHits().getAt(0) : null;
					if (hit != null) {
						return new ObjectMapper().convertValue(hit.getSource().get("origin"), JsonNode.class);
					}
				}
				return null;
			}
		});
	}

	public List<JsonNode> getIPActivitySummary(String from, String to, String ip) {

		QueryBuilder ipQuery = QueryBuilders.matchQuery("srcIP", ip);

		query = from == null && to == null ? ipQuery
				: QueryBuilders.filteredQuery(ipQuery, ESQueryCreator.createDateTimeRangeFilter(from, to));

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(QueryConstants.ALL_TYPES)
				.addAggregation(AggregationBuilders.filters("GlobalAgg")
						.filter(attackCategories[0], FilterBuilders.termFilter("_type", "SshIncident"))
						.filter(attackCategories[1], FilterBuilders.termFilter("_type", "SipIncident"))
						.filter(attackCategories[2], FilterBuilders.termFilter("_type", "WebIncident"))
						.filter(attackCategories[3],
								FilterBuilders.boolFilter().should(FilterBuilders.termFilter("_type", "MysqlIncident"),
										FilterBuilders.termFilter("_type", "MssqlIncident")))
						.filter(attackCategories[4],
								FilterBuilders.boolFilter()
										.should(FilterBuilders.queryFilter(QueryBuilders.wildcardQuery(
												"NetworkLayerIncident.signatureClass", "*attempted-recon*")),
								FilterBuilders.queryFilter(QueryBuilders
										.wildcardQuery("NetworkLayerIncident.signatureClass", "*misc-activity*")))
								.must(FilterBuilders.termFilter("_type", "NetworkLayerIncident")))
						.filter(attackCategories[5], FilterBuilders.termFilter("_type", "MalwareIncident")))
				.build();
		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {

				System.out.println(response.toString());
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				Map<String, Object> bucket = new HashMap<String, Object>();
				ObjectMapper myObjectMapper = new ObjectMapper();
				InternalFilters t = response.getAggregations().get("GlobalAgg");
				int i = 0;
				for (Filters.Bucket b : t.getBuckets()) {
					bucket.put("category", attackCategories[i]);
					bucket.put("hits", b.getDocCount());
					jnode.add(myObjectMapper.convertValue(bucket, JsonNode.class));
					i++;

				}

				bucket.put("category", "Total Attacks");
				bucket.put("hits", response.getHits().getTotalHits());
				jnode.add(myObjectMapper.convertValue(bucket, JsonNode.class));

				return jnode;
			}
		});

	}

	/**
	 * 
	 * @param from
	 * @param to
	 * @param ip
	 * @return
	 */
	public JsonNode getIPAnalysis(String ip) {

		JsonNode ipNode = null;
		HashMap<String, Object> map = new HashMap<String, Object>();
		double riskFactor;
		List<JsonNode> n = getIPActivitySummary(null, null, ip);
		// riskFactor =
		double rec = Integer.parseInt(n.get(4).get("hits").asText());
		double ssh = Integer.parseInt(n.get(0).get("hits").asText());
		double sip = Integer.parseInt(n.get(1).get("hits").asText());
		double web = Integer.parseInt(n.get(2).get("hits").asText());
		double db = Integer.parseInt(n.get(3).get("hits").asText());
		double mal = Integer.parseInt(n.get(5).get("hits").asText());
		double total = Integer.parseInt(n.get(6).get("hits").asText());
		// rec = rec == 0? total/10 :rec;
		riskFactor = rec == total ? 2.5
				: (((ssh / total) * 8 + (mal / total) * 10 + (sip / total) * 5 + (rec / total) * 2 + (db / total) * 3
						+ (web / total) * 7) / 12) * 10;

		JsonNode duration = getIPActivityTimeBounds(ip);
		long days = Long.parseLong(duration.get("daysSinceLastSeen").asText());
		System.out.println(duration.get("daysSinceLastSeen").asText());
		if (days < 30) {
			map.put("activity", "Active");
		} else if (days >= 30 && days < 60) {
			map.put("activity", "Sleep");
		} else if (days >= 60 && days < 120) {
			map.put("activity", "Hibernate");
		} else {
			map.put("activity", "Inactive");
		}

		// activity status

		map.put("firstSeen", duration.get("firstSeen").asText());
		map.put("lastSeen", duration.get("lastSeen").asText());
		map.put("riskFactor", riskFactor);
		map.put("confidence", "50%");

		ipNode = new ObjectMapper().convertValue(map, JsonNode.class);
		return ipNode;
	}

	/**
	 * 
	 * @param from
	 * @param to
	 * @param ip
	 * @return
	 */
	public JsonNode getIPActivityTimeBounds(String ip) {

		JsonNode ipNode = null;
		HashMap<String, Object> map = new HashMap<String, Object>();
		QueryBuilder ipQuery = QueryBuilders.matchQuery("srcIP", ip);

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(ipQuery).withSearchType(SearchType.QUERY_AND_FETCH)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(QueryConstants.ALL_TYPES)
				.withSort(SortBuilders.fieldSort("dateTime").order(SortOrder.ASC)).withPageable(new PageRequest(0, 1))
				.build();
		map = elasticsearchTemplate.query(searchQuery, new ResultsExtractor<HashMap<String, Object>>() {

			@Override
			public HashMap<String, Object> extract(SearchResponse response) {
				HashMap<String, Object> hmap = new HashMap<>();
				if (response.getHits() != null) {
					SearchHit hit = response.getHits().hits().length > 0 ? response.getHits().getAt(0) : null;
					if (hit != null) {
						hmap.put("firstSeen", hit.getSource().get("dateTime"));
					}
				}
				return hmap;

			}
		});

		searchQuery = new NativeSearchQueryBuilder().withQuery(ipQuery).withSearchType(SearchType.QUERY_AND_FETCH)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(QueryConstants.ALL_TYPES)
				.withSort(SortBuilders.fieldSort("dateTime").order(SortOrder.DESC)).build();
		map.putAll(elasticsearchTemplate.query(searchQuery, new ResultsExtractor<HashMap<String, Object>>() {

			@Override
			public HashMap<String, Object> extract(SearchResponse response) {
				HashMap<String, Object> hmap = new HashMap<>();
				if (response.getHits() != null) {
					SearchHit hit = response.getHits().hits().length > 0 ? response.getHits().getAt(0) : null;
					if (hit != null) {
						hmap.put("lastSeen", hit.getSource().get("dateTime"));
						DateTimeFormatter formatter = ISODateTimeFormat.dateOptionalTimeParser();
						DateTime lastSeen = formatter.parseDateTime((String) hmap.get("lastSeen"));
						Duration d = new Duration(lastSeen, DateTime.now().plusHours(5));
						hmap.put("daysSinceLastSeen", d.getStandardDays());
					}
					return hmap;
				}
				return null;

			}
		}));

		ipNode = new ObjectMapper().convertValue(map, JsonNode.class);
		return ipNode;
	}

	/**
	 * 
	 * @param from
	 * @param to
	 * @param ip
	 * @return
	 */
	public JsonNode getIPProbingAttempts(String from, String to, String ip) {

		QueryBuilder ipQuery = QueryBuilders.termQuery("srcIP", ip);

		HashMap<String, Object> map = new HashMap<String, Object>();
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

		return new ObjectMapper().convertValue(map, JsonNode.class);

	}

	/**
	 * 
	 * @param from
	 * @param to
	 * @param ip
	 * @return
	 */
	public List<JsonNode> getIPActivityTimeline(String from, String to, String ip) {

		DateTimeFormatter formatter = ISODateTimeFormat.dateOptionalTimeParser();

		QueryBuilder ipQuery = QueryBuilders.matchQuery("srcIP", ip);
		JsonNode duration = getIPActivityTimeBounds(ip);
		Interval interval = null;
		// Get duration
		if (duration.has("firstSeen") && duration.has("lastSeen")) {
			DateTime firstSeen = formatter.parseDateTime(duration.get("firstSeen").asText());
			DateTime lastSeen = formatter.parseDateTime(duration.get("lastSeen").asText());
			Duration d = new Duration(firstSeen, lastSeen);
			long days = d.getStandardDays();
			// algo for interval, max 25 points
			// for only one hit
			if (firstSeen.compareTo(lastSeen) == 0) {
				interval = Interval.SECOND;
			} else if (days < 25) {
				long minutes = d.getStandardMinutes();
				if (minutes < (25 * 60)) {
					interval = Interval.minutes((int) ((minutes / 25) == 0 ? 1 : (minutes / 25)));
				}
				long hours = d.getStandardHours();
				interval = Interval.hours((int) ((hours / 25) == 0 ? 1 : (hours / 25)));

			} else if (days >= 25 && days < 176) {
				interval = Interval.days((int) ((days / 25) == 0 ? 1 : (days / 25)));
			}

			else if (days >= 176 && days < 365) {

				interval = Interval.weeks((int) (((days / 7) / 25) == 0 ? 1 : ((days / 7) / 25)));
			}

			else {
				interval = Interval.MONTH;
			}

			DateHistogramBuilder histo = AggregationBuilders.dateHistogram("pulse").field("dateTime").interval(interval)
					.order(Histogram.Order.KEY_ASC).minDocCount(0);

			// build query
			searchQuery = new NativeSearchQueryBuilder().withQuery(ipQuery)
					.withSearchType(SearchType.DFS_QUERY_AND_FETCH).withIndices(QueryConstants.INCIDENT_INDEX)
					.withTypes(QueryConstants.ALL_TYPES).addAggregation(histo).build();
			return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

				@Override
				public List<JsonNode> extract(SearchResponse response) {
					List<JsonNode> node = new ArrayList<JsonNode>();
					HashMap<String, Object> map = new HashMap<String, Object>();
					if (response.getAggregations() != null) {
						DateHistogram t = response.getAggregations().get("pulse");

						for (Bucket b : t.getBuckets()) {
							map.put("x-time", (b.getKey()));
							map.put("y-hits", (b.getDocCount()));
							node.add(new ObjectMapper().convertValue(map, JsonNode.class));
						}

					}
					return node;

				}
			});
		}
		return null;
	}

}
