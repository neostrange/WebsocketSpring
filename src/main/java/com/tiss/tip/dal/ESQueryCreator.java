package com.tiss.tip.dal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.search.SearchType;
import org.elasticsearch.common.collect.ImmutableMap;
import org.elasticsearch.common.joda.time.DateTime;
import org.elasticsearch.index.mapper.ip.IpFieldMapper;
import org.elasticsearch.index.query.FilterBuilder;
import org.elasticsearch.index.query.FilterBuilders;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.index.query.RangeFilterBuilder;
import org.elasticsearch.search.aggregations.AggregationBuilders;
import org.elasticsearch.search.aggregations.bucket.filters.Filters.Bucket;
import org.elasticsearch.search.aggregations.bucket.filters.Filters;
import org.elasticsearch.search.aggregations.bucket.filters.InternalFilters;
import org.elasticsearch.search.aggregations.bucket.nested.Nested;
import org.elasticsearch.search.aggregations.bucket.terms.Terms;
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

/**
 * For creation of ES queries
 * 
 * @author YG
 *
 */

@Component
public class ESQueryCreator {

	private static QueryBuilder query;

	private static SearchQuery searchQuery;

	private static FilterBuilder filter;

	public static final String[] attackCategories = { "SSH Attacks", "SIP Attacks", "Web Attacks", "Database Attacks",
			"Reconnaissance", "Malware Infection", "Total Attacks" };

	@Autowired
	private ElasticsearchTemplate elasticsearchTemplate;

	private static final Logger logger = LoggerFactory.getLogger(ESQueryCreator.class);

	public static final ImmutableMap<Object, Object> ES_TYPES = ImmutableMap.builder().put("malware", "MalwareIncident")
			.put("web", "WebIncident").put("mssql", "MssqlIncident").put("mysql", "MysqlIncident")
			.put("network", "NetworkLayerIncident").put("sip", "SipIncident").put("ssh", "SshIncident").build();

	public static ResultsExtractor<List<JsonNode>> topIPExtractor = new ResultsExtractor<List<JsonNode>>() {

		@Override
		public List<JsonNode> extract(SearchResponse response) {
			ObjectMapper myObjectMapper = new ObjectMapper();
			List<JsonNode> jnode = new ArrayList<JsonNode>();
			HashMap<String, Object> buckets = null;
			if (response.getAggregations() != null) {
				Terms terms = response.getAggregations().get("TopIPs");
				String tmp = "";
				Terms t = null;
				Terms.Bucket buck = null;
				logger.warn("Document Count Error is [{}]", terms.getDocCountError());
				for (Terms.Bucket b : terms.getBuckets()) {
					buckets = new HashMap<String, Object>();
					tmp = IpFieldMapper.longToIp(Long.parseLong(b.getKey()));
					buckets.put("ip", tmp);
					buckets.put("hits", b.getDocCount());
					if (b.getAggregations() != null) {
						t = b.getAggregations().get("Country");
						buck = t.getBuckets().size() > 0 ? t.getBuckets().get(0) : null;
						if (buck != null) {
							buckets.put("country", buck.getKey());
							t = buck.getAggregations().get("CountryCode");
							if (t.getBuckets().size() > 0)
								buckets.put("countryCode", t.getBuckets().get(0).getKey());
						}
					}
					jnode.add(myObjectMapper.convertValue(buckets, JsonNode.class));
				}
			}
			return jnode;
		}
	};

	public static ResultsExtractor<List<JsonNode>> topCountryUniqueIPExtractor = new ResultsExtractor<List<JsonNode>>() {

		@Override
		public List<JsonNode> extract(SearchResponse response) {
			ObjectMapper myObjectMapper = new ObjectMapper();
			List<JsonNode> jnode = new ArrayList<JsonNode>();
			HashMap<String, Object> bucket = null;
			HashMap<String, Object> subBucket = null;
			if (response.getAggregations() != null) {
				Terms terms = response.getAggregations().get("TopCountries");
				String ip = "";
				logger.warn("Document Count Error is [{}]", terms.getDocCountError());
				for (Terms.Bucket b : terms.getBuckets()) {
					bucket = new HashMap<String, Object>();
					bucket.put("countryCode", b.getKey());
					bucket.put("hits", b.getDocCount());
					Terms t = b.getAggregations().get("Country");
					bucket.put("country", t.getBuckets().get(0).getKey());
					// if subaggregation exists
					if (b.getAggregations() != null) {
						List<JsonNode> subNode = new ArrayList<JsonNode>();
						t = b.getAggregations().get("IP");
						// for sub aggregation result
						for (Terms.Bucket sub : t.getBuckets()) {
							subBucket = new HashMap<String, Object>();
							ip = IpFieldMapper.longToIp(Long.parseLong(sub.getKey()));

							subBucket.put("ip", ip);
							subBucket.put("hits", sub.getDocCount());
							subNode.add(myObjectMapper.convertValue(subBucket, JsonNode.class));

						}

						bucket.put("uniqueIps", subNode);
					}

					jnode.add(myObjectMapper.convertValue(bucket, JsonNode.class));
				}
			}
			return jnode;
		}
	};

	public static ResultsExtractor<List<JsonNode>> topCountryExtractor = new ResultsExtractor<List<JsonNode>>() {

		@Override
		public List<JsonNode> extract(SearchResponse response) {

			ObjectMapper myObjectMapper = new ObjectMapper();
			List<JsonNode> jnode = new ArrayList<JsonNode>();
			HashMap<String, Object> buckets = null;
			if (response.getAggregations() != null) {
				Terms terms = response.getAggregations().get("TopCountries");
				logger.warn("Document Count Error is [{}]", terms.getDocCountError());
				for (Terms.Bucket b : terms.getBuckets()) {
					buckets = new HashMap<String, Object>();
					buckets.put("countryCode", b.getKey());
					if (b.getAggregations() != null) {
						Terms t = b.getAggregations().get("Country");
						buckets.put("country", t.getBuckets().get(0).getKey());
					}
					buckets.put("hits", b.getDocCount());
					jnode.add(myObjectMapper.convertValue(buckets, JsonNode.class));
				}
			}
			return jnode;
		}

	};

	/**
	 * Filter for dateTime from greater than equal to {@code gte} to less than
	 * equal to {@code lte}
	 * 
	 * @param gte
	 *            greater than equal to this
	 * @param lte
	 *            less than equal to this
	 * @return FilterBuilder to be added to a QueryBuilder
	 */
	public static FilterBuilder createDateTimeRangeFilter(String gte, String lte) {
		FilterBuilder filter = new RangeFilterBuilder(QueryConstants.DATETIME).gte(gte).lte(lte);
		System.out.println(filter);
		return filter;
	}

	/**
	 * Filter for dateTime {@code now} minus {@code refreshInterval}
	 * 
	 * @param refreshInterval
	 *            now minus this will be the filter range (in seconds)
	 * @return FilterBuilder to be added to a QueryBuilder
	 */
	public static FilterBuilder createDateTimeRTFilter(int refreshInterval) {
		DateTime dateTime = DateTime.now().plusHours(5);
		logger.info("Now: {} and Now-1minute: {}", dateTime, dateTime.minusSeconds(refreshInterval));
		return FilterBuilders.rangeFilter(QueryConstants.DATETIME).gte(dateTime.minusSeconds(refreshInterval))
				.lt(dateTime);

	}

	public List<JsonNode> createRTIncidentsQuery(int interval) {
		query = QueryBuilders.matchAllQuery();
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withFilter(createDateTimeRTFilter(interval))
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(QueryConstants.ALL_TYPES).build();
		logger.info(searchQuery.getQuery().toString() + searchQuery.getFilter().toString());
		return elasticsearchTemplate.queryForList(searchQuery, JsonNode.class);

	}

	/**
	 * Returns most frequent IPs in the specified type (or types) of incidents,
	 * and their corresponding countries
	 * 
	 * @param type
	 * @param from
	 * @param to
	 * @param size
	 * @return
	 */
	public List<JsonNode> getTopIPCountries(String type, String from, String to, int size, int minCount) {
		query = from == null && to == null ? null
				: QueryBuilders.filteredQuery(null, createDateTimeRangeFilter(from, to));
		// Setting types to fetch data from
		String[] tmp = new String[1];
		if (ES_TYPES.containsKey(type)) {
			tmp[0] = (String) ES_TYPES.get(type);
		} else {
			tmp = QueryConstants.ALL_TYPES;
		}

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(tmp)
				.addAggregation(
						AggregationBuilders.terms("TopIPs").size(size).minDocCount(minCount)
								.showTermDocCountError(true).field(
										"srcIP")
								.subAggregation(AggregationBuilders.terms("Country").field("origin.srcCountry")
										.subAggregation(AggregationBuilders.terms("CountryCode")
												.field("origin.srcCountryCode"))))
				.build();

		return elasticsearchTemplate.query(searchQuery, topIPExtractor);

	}

	/**
	 * Returns top countries in the specified type (or types) of incidents, and
	 * the associated distinct IPs that have attacked
	 * 
	 * @param type
	 * @param from
	 * @param to
	 * @param size
	 * @return
	 */
	public List<JsonNode> getTopCountryUniqueIPs(String type, String from, String to, int size) {
		query = from == null && to == null ? null
				: QueryBuilders.filteredQuery(null, createDateTimeRangeFilter(from, to));
		// Setting types to fetch data from
		String[] tmp = new String[1];
		if (ES_TYPES.containsKey(type)) {
			tmp[0] = (String) ES_TYPES.get(type);
		} else {
			tmp = QueryConstants.ALL_TYPES;
		}

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(tmp)
				.addAggregation(AggregationBuilders.terms("TopCountries").size(size).showTermDocCountError(true)
						.field("origin.srcCountryCode")
						.subAggregation(AggregationBuilders.terms("Country").field("origin.srcCountry"))
						.subAggregation(AggregationBuilders.terms("IP").field("srcIP")))
				.build();
		return elasticsearchTemplate.query(searchQuery, topCountryUniqueIPExtractor);

	}

	/**
	 * Returns most frequent attacking countries in the specified type (or
	 * types) of incidents
	 * 
	 * @param type
	 * @param from
	 * @param to
	 * @param size
	 * @return
	 */
	public List<JsonNode> getTopCountries(String type, String from, String to, int size) {

		query = from == null && to == null ? null
				: QueryBuilders.filteredQuery(null, createDateTimeRangeFilter(from, to));
		// Setting types to fetch data from
		String[] tmp = new String[1];
		if (ES_TYPES.containsKey(type)) {
			tmp[0] = (String) ES_TYPES.get(type);
		} else {
			tmp = QueryConstants.ALL_TYPES;
		}

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(tmp)
				.addAggregation(AggregationBuilders.terms("TopCountries").size(size).showTermDocCountError(true)
						.field("origin.srcCountryCode")
						.subAggregation(AggregationBuilders.terms("Country").field("origin.srcCountry")))
				.build();

		return elasticsearchTemplate.query(searchQuery, topCountryExtractor);

	}

	public List<JsonNode> getRTCounts(int interval) {

		final String[] attacks = { "malware", "sip", "web" };
		query = QueryBuilders.filteredQuery(null, createDateTimeRTFilter(interval));
		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(QueryConstants.ALL_TYPES)
				.addAggregation(AggregationBuilders.filters("Agg")
						.filter(attacks[0], FilterBuilders.termFilter("_type", "MalwareIncident"))
						.filter(attacks[1], FilterBuilders.termFilter("_type", "SipIncident"))
						.filter(attacks[2], FilterBuilders.termFilter("_type", "WebIncident")))
				.build();
		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {

				System.out.println(response.toString());
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				Map<String, Object> bucket = new HashMap<String, Object>();
				ObjectMapper myObjectMapper = new ObjectMapper();
				InternalFilters t = response.getAggregations().get("Agg");
				int i = 0;
				for (Filters.Bucket b : t.getBuckets()) {
					bucket.put(attacks[i], b.getDocCount());
					i++;

				}

				jnode.add(myObjectMapper.convertValue(bucket, JsonNode.class));
				return jnode;
			}
		});

	}

	/**
	 * Returns most frequent attacking countries in the specified type (or
	 * types) of incidents
	 * 
	 * @param type
	 * @param from
	 * @param to
	 * @param size
	 * @return
	 */
	public List<JsonNode> getMalwareHashes(String malName, String from, String to, int size, String countryCode) {
		QueryBuilder country = countryCode != null ? QueryBuilders.termQuery("origin.srcCountryCode", countryCode)
				: null;
		filter = FilterBuilders.boolFilter()
				.must(FilterBuilders.queryFilter(
						QueryBuilders.wildcardQuery("vtScan.VTscanResults.Kaspersky", "*" + malName + "*")))
				.must(createDateTimeRangeFilter(from, to));
		query = from == null && to == null
				? QueryBuilders.filteredQuery(country,
						FilterBuilders.termFilter("vtScan.VTscanResults.Kaspersky", malName))
				: QueryBuilders.filteredQuery(country, filter);

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes((String) ES_TYPES.get("malware"))
				.addAggregation(
						AggregationBuilders.terms("Hashes").size(size).showTermDocCountError(true).field("md5Hash"))
				.build();

		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {
				ObjectMapper myObjectMapper = new ObjectMapper();
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				HashMap<String, Object> buckets = null;
				if (response.getAggregations() != null) {
					Terms terms = response.getAggregations().get("Hashes");
					logger.warn("Document Count Error is [{}]", terms.getDocCountError());
					for (Terms.Bucket b : terms.getBuckets()) {
						buckets = new HashMap<String, Object>();
						buckets.put("hash", b.getKey());
						buckets.put("hits", b.getDocCount());
						jnode.add(myObjectMapper.convertValue(buckets, JsonNode.class));
					}
					return jnode;
				}
				return jnode;
			}
		});

	}

	/**
	 * Returns most frequent attacking countries in the specified type (or
	 * types) of incidents
	 * 
	 * @param type
	 * @param from
	 * @param to
	 * @param size
	 * @return
	 */
	public List<JsonNode> getTopMalwares(String from, String to, int size) {

		query = from == null && to == null ? null
				: QueryBuilders.filteredQuery(null, createDateTimeRangeFilter(from, to));

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes((String) ES_TYPES.get("malware"))
				.addAggregation(AggregationBuilders.terms("TopMalwares").size(size).showTermDocCountError(true)
						.field("vtScan.VTscanResults.Kaspersky"))
				.build();

		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {
				ObjectMapper myObjectMapper = new ObjectMapper();
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				HashMap<String, Object> buckets = null;
				Terms terms = response.getAggregations().get("TopMalwares");
				logger.warn("Document Count Error is [{}]", terms.getDocCountError());
				for (Terms.Bucket b : terms.getBuckets()) {
					buckets = new HashMap<String, Object>();
					buckets.put("malware", b.getKey());
					buckets.put("hits", b.getDocCount());
					jnode.add(myObjectMapper.convertValue(buckets, JsonNode.class));
				}
				return jnode;
			}
		});

	}

	/**
	 * Returns most frequent attacking countries in the specified type (or
	 * types) of incidents
	 * 
	 * @param type
	 * @param from
	 * @param to
	 * @param size
	 * @return
	 */
	public List<JsonNode> getTopServicesAttacked(String from, String to, int size) {

		query = from == null && to == null ? null
				: QueryBuilders.filteredQuery(null, createDateTimeRangeFilter(from, to));
		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(QueryConstants.ALL_TYPES)
				.addAggregation(AggregationBuilders.terms("TopServices").size(size).showTermDocCountError(true)
						.field("service"))
				.build();

		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {

				ObjectMapper myObjectMapper = new ObjectMapper();
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				HashMap<String, Object> buckets = null;
				Terms terms = response.getAggregations().get("TopServices");
				logger.warn("Document Count Error is [{}]", terms.getDocCountError());
				for (Terms.Bucket b : terms.getBuckets()) {
					buckets = new HashMap<String, Object>();
					buckets.put("service", b.getKey());
					buckets.put("hits", b.getDocCount());
					jnode.add(myObjectMapper.convertValue(buckets, JsonNode.class));
				}
				return jnode;
			}
		});

	}

	/**
	 * Returns most frequent IPs in the specified type (or types) of incidents,
	 * and their corresponding countries
	 * 
	 * @param type
	 * @param from
	 * @param to
	 * @param size
	 * @return
	 */
	public List<JsonNode> getTopProbingIPs(String from, String to, int size, int minDocCount) {

		filter = FilterBuilders.boolFilter().should(FilterBuilders.termFilter("signatureClass", "attempted-recon"))
				.should(FilterBuilders.termFilter("signatureClass", "misc-activity"));

		query = from == null && to == null ? QueryBuilders.filteredQuery(null, filter)
				: QueryBuilders.filteredQuery(null,
						FilterBuilders.andFilter(filter, createDateTimeRangeFilter(from, to)));

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes((String) ES_TYPES.get("network"))
				.addAggregation(
						AggregationBuilders.terms("TopIPs").size(size).minDocCount(minDocCount)
								.showTermDocCountError(true).field(
										"srcIP")
								.subAggregation(AggregationBuilders.terms("Country").field("origin.srcCountry")
										.subAggregation(AggregationBuilders.terms("CountryCode")
												.field("origin.srcCountryCode"))))
				.build();
		return elasticsearchTemplate.query(searchQuery, topIPExtractor);

	}

	/**
	 * Returns most frequent IPs in the specified type (or types) of incidents,
	 * and their corresponding countries
	 * 
	 * @param type
	 * @param from
	 * @param to
	 * @param size
	 * @return
	 */
	public List<JsonNode> getTopProbingCountriesUniqueIPs(String from, String to, int size) {

		filter = FilterBuilders.boolFilter().should(FilterBuilders.termFilter("signatureClass", "attempted-recon"))
				.should(FilterBuilders.termFilter("signatureClass", "misc-activity"));

		query = from == null && to == null ? QueryBuilders.filteredQuery(null, filter)
				: QueryBuilders.filteredQuery(null,
						FilterBuilders.andFilter(filter, createDateTimeRangeFilter(from, to)));

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes((String) ES_TYPES.get("network"))
				.addAggregation(AggregationBuilders.terms("TopCountries").size(size).showTermDocCountError(true)
						.field("origin.srcCountryCode")
						.subAggregation(AggregationBuilders.terms("Country").field("origin.srcCountry"))
						.subAggregation(AggregationBuilders.terms("IP").field("srcIP")))
				.build();
		return elasticsearchTemplate.query(searchQuery, topCountryUniqueIPExtractor);

	}

	/**
	 * 
	 * @param type
	 * @param from
	 * @param size
	 * @return
	 */
	public List<JsonNode> getTopProbingCountries(String from, String to, int size) {

		filter = FilterBuilders.boolFilter().should(FilterBuilders.termFilter("signatureClass", "attempted-recon"))
				.should(FilterBuilders.termFilter("signatureClass", "misc-activity"));

		query = from == null && to == null ? QueryBuilders.filteredQuery(null, filter)
				: QueryBuilders.filteredQuery(null,
						FilterBuilders.andFilter(filter, createDateTimeRangeFilter(from, to)));

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes((String) ES_TYPES.get("network"))
				.addAggregation(AggregationBuilders.terms("TopCountries").size(size).showTermDocCountError(true)
						.field("origin.srcCountryCode")
						.subAggregation(AggregationBuilders.terms("Country").field("origin.srcCountry")))
				.build();

		return elasticsearchTemplate.query(searchQuery, topCountryExtractor);

	}

	/**
	 * 
	 * @param from
	 * @param to
	 * @param size
	 * @return
	 */
	public List<JsonNode> getTopSipTools(String from, String to, int size, String countryCode) {

		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;

		query = from == null && to == null ? country
				: QueryBuilders.filteredQuery(country, createDateTimeRangeFilter(from, to));
		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes((String) ES_TYPES.get("sip"))
				.addAggregation(AggregationBuilders.terms("TopSipTools").size(size).showTermDocCountError(true)
						.field("sipUserAgent"))
				.build();

		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {

				ObjectMapper myObjectMapper = new ObjectMapper();
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				HashMap<String, Object> buckets = null;
				Terms terms = response.getAggregations().get("TopSipTools");
				logger.warn("Document Count Error is [{}]", terms.getDocCountError());
				for (Terms.Bucket b : terms.getBuckets()) {
					buckets = new HashMap<String, Object>();
					buckets.put("tools", b.getKey());
					buckets.put("hits", b.getDocCount());
					jnode.add(myObjectMapper.convertValue(buckets, JsonNode.class));
				}
				return jnode;
			}
		});

	}

	/**
	 * 
	 * @param from
	 * @param to
	 * @param size
	 * @return
	 */
	public List<JsonNode> getTopSipMethods(String from, String to, int size, String countryCode) {
		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;

		query = from == null && to == null ? country
				: QueryBuilders.filteredQuery(country, createDateTimeRangeFilter(from, to));
		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes((String) ES_TYPES.get("sip"))
				.addAggregation(AggregationBuilders.terms("TopSipMethods").size(size).showTermDocCountError(true)
						.field("sipMethod"))
				.build();

		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {

				ObjectMapper myObjectMapper = new ObjectMapper();
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				HashMap<String, Object> buckets = null;
				Terms terms = response.getAggregations().get("TopSipMethods");
				logger.warn("Document Count Error is [{}]", terms.getDocCountError());
				for (Terms.Bucket b : terms.getBuckets()) {
					buckets = new HashMap<String, Object>();
					buckets.put("method", b.getKey());
					buckets.put("hits", b.getDocCount());
					jnode.add(myObjectMapper.convertValue(buckets, JsonNode.class));
				}
				return jnode;
			}
		});

	}

	/**
	 * 
	 * @param type
	 * @param from
	 * @param size
	 * @return
	 */
	public List<JsonNode> getSipRegistrarFloodingAttacks(String from, String to, int size, String countryCode) {

		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;

		filter = FilterBuilders.termFilter("sipMethod", "REGISTER");

		query = from == null && to == null ? QueryBuilders.filteredQuery(country, filter)
				: QueryBuilders.filteredQuery(country,
						FilterBuilders.andFilter(filter, createDateTimeRangeFilter(from, to)));

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes((String) ES_TYPES.get("sip"))
				.addAggregation(
						AggregationBuilders.terms("TopIPs").size(size)
								.showTermDocCountError(true).field(
										"srcIP")
								.subAggregation(AggregationBuilders.terms("Country").field("origin.srcCountry")
										.subAggregation(AggregationBuilders.terms("CountryCode")
												.field("origin.srcCountryCode"))))
				.build();

		return elasticsearchTemplate.query(searchQuery, topIPExtractor);

	}

	/**
	 * 
	 * @param type
	 * @param from
	 * @param size
	 * @return
	 */
	public List<JsonNode> getSipOptionsFloodingAttacks(String from, String to, int size, String countryCode) {

		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;

		filter = FilterBuilders.termFilter("sipMethod", "OPTIONS");

		query = from == null && to == null ? QueryBuilders.filteredQuery(country, filter)
				: QueryBuilders.filteredQuery(country,
						FilterBuilders.andFilter(filter, createDateTimeRangeFilter(from, to)));

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes((String) ES_TYPES.get("sip"))
				.addAggregation(
						AggregationBuilders.terms("TopIPs").size(size)
								.showTermDocCountError(true).field(
										"srcIP")
								.subAggregation(AggregationBuilders.terms("Country").field("origin.srcCountry")
										.subAggregation(AggregationBuilders.terms("CountryCode")
												.field("origin.srcCountryCode"))))
				.build();

		return elasticsearchTemplate.query(searchQuery, topIPExtractor);

	}

	/**
	 * 
	 * @param type
	 * @param from
	 * @param size
	 * @return
	 */
	public List<JsonNode> getSipProxyFloodingAttacks(String from, String to, int size, String countryCode) {

		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;

		filter = FilterBuilders.termFilter("sipMethod", "INVITE");

		query = from == null && to == null ? QueryBuilders.filteredQuery(country, filter)
				: QueryBuilders.filteredQuery(country,
						FilterBuilders.andFilter(filter, createDateTimeRangeFilter(from, to)));

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes((String) ES_TYPES.get("sip"))
				.addAggregation(
						AggregationBuilders.terms("TopIPs").size(size)
								.showTermDocCountError(true).field(
										"srcIP")
								.subAggregation(AggregationBuilders.terms("Country").field("origin.srcCountry")
										.subAggregation(AggregationBuilders.terms("CountryCode")
												.field("origin.srcCountryCode"))))
				.build();

		return elasticsearchTemplate.query(searchQuery, topIPExtractor);

	}

	/**
	 * 
	 * @param type
	 * @param from
	 * @param size
	 * @return
	 */
	public List<JsonNode> getSipAckFloodingAttacks(String from, String to, int size, String countryCode) {
		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;
		filter = FilterBuilders.termFilter("sipMethod", "ACK");

		query = from == null && to == null ? QueryBuilders.filteredQuery(country, filter)
				: QueryBuilders.filteredQuery(country,
						FilterBuilders.andFilter(filter, createDateTimeRangeFilter(from, to)));

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes((String) ES_TYPES.get("sip"))
				.addAggregation(
						AggregationBuilders.terms("TopIPs").size(size)
								.showTermDocCountError(true).field(
										"srcIP")
								.subAggregation(AggregationBuilders.terms("Country").field("origin.srcCountry")
										.subAggregation(AggregationBuilders.terms("CountryCode")
												.field("origin.srcCountryCode"))))
				.build();

		return elasticsearchTemplate.query(searchQuery, topIPExtractor);

	}

	/**
	 * 
	 * @param from
	 * @param to
	 * @param size
	 * @return
	 */
	public List<JsonNode> getTopSshUsernames(String from, String to, int size, String countryCode) {
		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;
		query = from == null && to == null ? country
				: QueryBuilders.filteredQuery(country, ESQueryCreator.createDateTimeRangeFilter(from, to));
		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.QUERY_AND_FETCH)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes((String) ES_TYPES.get("ssh"))
				.addAggregation(AggregationBuilders.nested("TopUsernames").path("authList")
						.subAggregation(AggregationBuilders.terms("Usernames").field("authList.username").size(size)))
				.build();

		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {

				ObjectMapper myObjectMapper = new ObjectMapper();
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				HashMap<String, Object> buckets = null;
				Nested nest = response.getAggregations().get("TopUsernames");
				Terms terms = nest.getAggregations().get("Usernames");
				// logger.warn("Document Count Error is [{}]",
				// terms.getDocCountError());
				for (Terms.Bucket b : terms.getBuckets()) {
					buckets = new HashMap<String, Object>();
					buckets.put("username", b.getKey());
					buckets.put("hits", b.getDocCount());
					jnode.add(myObjectMapper.convertValue(buckets, JsonNode.class));
				}
				return jnode;
			}
		});

	}

	/**
	 * 
	 * @param from
	 * @param to
	 * @param size
	 * @return
	 */
	public List<JsonNode> getTopSshUsernamePasswordPairs(String from, String to, int size) {

		query = from == null && to == null ? null
				: QueryBuilders.filteredQuery(null, createDateTimeRangeFilter(from, to));
		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX)
				.withTypes(
						(String) ES_TYPES.get("ssh"))
				.addAggregation(AggregationBuilders.nested("TopUsernames").path("authList").subAggregation(
						AggregationBuilders.terms("Usernames").field("authList.username").subAggregation(
								AggregationBuilders.terms("Passwords").field("authList.password").size(size))))
				.build();

		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {

				ObjectMapper myObjectMapper = new ObjectMapper();
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				HashMap<String, Object> buckets = null;
				// HashMap<String, Object> subBucket = null;
				Nested nest = response.getAggregations().get("TopUsernames");
				Terms terms = nest.getAggregations().get("Usernames");
				// logger.warn("Document Count Error is [{}]",
				// terms.getDocCountError());
				String uname = null;
				for (Terms.Bucket b : terms.getBuckets()) {
					uname = b.getKey();
					// for sub aggregation result
					if (b.getAggregations() != null) {
						Terms t = b.getAggregations().get("Passwords");
						for (Terms.Bucket sub : t.getBuckets()) {
							buckets = new HashMap<String, Object>();
							buckets.put("username", uname);
							buckets.put("password", sub.getKey());
							buckets.put("hits", sub.getDocCount());
							jnode.add(myObjectMapper.convertValue(buckets, JsonNode.class));
						}
					}
				}
				return jnode;
			}
		});

	}

	public List<JsonNode> getTopSshPasswords(String from, String to, int size, String countryCode) {

		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;
		query = from == null && to == null ? country
				: QueryBuilders.filteredQuery(country, ESQueryCreator.createDateTimeRangeFilter(from, to));
		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes((String) ES_TYPES.get("ssh"))
				.addAggregation(AggregationBuilders.nested("TopPasswords").path("authList")
						.subAggregation(AggregationBuilders.terms("Passwords").field("authList.password").size(size)))
				.build();

		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {

				ObjectMapper myObjectMapper = new ObjectMapper();
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				HashMap<String, Object> buckets = null;
				Nested nest = response.getAggregations().get("TopPasswords");
				Terms terms = nest.getAggregations().get("Passwords");
				// logger.warn("Document Count Error is [{}]",
				// terms.getDocCountError());
				for (Terms.Bucket b : terms.getBuckets()) {
					buckets = new HashMap<String, Object>();
					buckets.put("password", b.getKey());
					buckets.put("hits", b.getDocCount());
					jnode.add(myObjectMapper.convertValue(buckets, JsonNode.class));
				}
				return jnode;
			}
		});

	}

	public List<JsonNode> getTopSshInputs(String from, String to, int size, String countryCode) {

		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;
		query = from == null && to == null ? country
				: QueryBuilders.filteredQuery(country, ESQueryCreator.createDateTimeRangeFilter(from, to));
		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes((String) ES_TYPES.get("ssh"))
				.addAggregation(AggregationBuilders.nested("TopInputs").path("inputList")
						.subAggregation(AggregationBuilders.terms("In").field("inputList.command").size(size)))
				.build();

		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {

				ObjectMapper myObjectMapper = new ObjectMapper();
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				HashMap<String, Object> buckets = null;
				Nested nest = response.getAggregations().get("TopInputs");
				Terms terms = nest.getAggregations().get("In");
				// logger.warn("Document Count Error is [{}]",
				// terms.getDocCountError());
				for (Terms.Bucket b : terms.getBuckets()) {
					buckets = new HashMap<String, Object>();
					buckets.put("input", b.getKey());
					buckets.put("hits", b.getDocCount());
					jnode.add(myObjectMapper.convertValue(buckets, JsonNode.class));
				}
				return jnode;
			}
		});

	}

	/**
	 * 
	 * @param from
	 * @param to
	 * @param size
	 * @return
	 */
	public List<JsonNode> getTopSshTools(String from, String to, int size, String countryCode) {
		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;
		query = from == null && to == null ? country
				: QueryBuilders.filteredQuery(country, ESQueryCreator.createDateTimeRangeFilter(from, to));
		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(query).withSearchType(SearchType.COUNT)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes((String) ES_TYPES.get("ssh"))
				.addAggregation(
						AggregationBuilders.terms("TopSshTools").size(size).showTermDocCountError(true).field("tool"))
				.build();

		return elasticsearchTemplate.query(searchQuery, new ResultsExtractor<List<JsonNode>>() {

			@Override
			public List<JsonNode> extract(SearchResponse response) {

				ObjectMapper myObjectMapper = new ObjectMapper();
				List<JsonNode> jnode = new ArrayList<JsonNode>();
				HashMap<String, Object> buckets = null;
				Terms terms = response.getAggregations().get("TopSshTools");
				logger.warn("Document Count Error is [{}]", terms.getDocCountError());
				for (Terms.Bucket b : terms.getBuckets()) {
					buckets = new HashMap<String, Object>();
					buckets.put("tools", b.getKey());
					buckets.put("hits", b.getDocCount());
					jnode.add(myObjectMapper.convertValue(buckets, JsonNode.class));
				}
				return jnode;
			}
		});

	}

	/**
	 * 
	 * @param from
	 * @param to
	 * @param size
	 * @return
	 */
	public List<JsonNode> getTopWebAttacks(String from, String to, String countryCode) {

		QueryBuilder country = countryCode != null ? QueryBuilders.matchQuery("origin.srcCountryCode", countryCode)
				: null;
		query = from == null && to == null ? country
				: QueryBuilders.filteredQuery(country, createDateTimeRangeFilter(from, to));

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

}
