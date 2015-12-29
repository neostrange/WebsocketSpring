package com.tiss.tip.dal;
import java.util.HashMap;
import java.util.List;

import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.search.SearchType;
import org.elasticsearch.common.joda.time.DateTime;
import org.elasticsearch.index.query.FilterBuilder;
import org.elasticsearch.index.query.FilterBuilders;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.sort.SortBuilders;
import org.elasticsearch.search.sort.SortOrder;
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
import com.tiss.tip.model.Incident;
import com.tiss.tip.utils.QueryConstants;

@Component
public class IPQueryCreator {

	private static QueryBuilder query;

	private static SearchQuery searchQuery;

	@Autowired
	private ElasticsearchTemplate elasticsearchTemplate;

	private static final Logger logger = LoggerFactory.getLogger(IPQueryCreator.class);

	public List<Incident> getIPHistory(String from, String to, String ip, int size) {

		QueryBuilder ipQuery = QueryBuilders.matchQuery("srcIP", ip);

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(ipQuery).withSearchType(SearchType.QUERY_AND_FETCH)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(QueryConstants.ALL_TYPES)
				.withSort(SortBuilders.fieldSort("dateTime").order(SortOrder.DESC))
				.withPageable(new PageRequest(0, size)).build();
		return elasticsearchTemplate.queryForList(searchQuery, Incident.class);
	}

	public JsonNode getIPAnalysis(String from, String to, String ip) {

		JsonNode ipNode = null;
		final HashMap<String, Object> map = new HashMap<String, Object>();
		QueryBuilder ipQuery = QueryBuilders.matchQuery("srcIP", ip);

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(ipQuery).withSearchType(SearchType.QUERY_AND_FETCH)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(QueryConstants.ALL_TYPES)
				.withSort(SortBuilders.fieldSort("dateTime").order(SortOrder.ASC)).withPageable(new PageRequest(0, 1)).build();
		JsonNode n = elasticsearchTemplate.query(searchQuery, new ResultsExtractor<JsonNode>() {

			@Override
			public JsonNode extract(SearchResponse response) {
				if (response.getHits() != null) {
					SearchHit hit = response.getHits().getAt(0);
					map.put("firstSeen", hit.getSource().get("dateTime"));
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
	
	
	public JsonNode getIPActivityDuration(String from, String to, String ip) {

		JsonNode ipNode = null;
		final HashMap<String, Object> map = new HashMap<String, Object>();
		QueryBuilder ipQuery = QueryBuilders.matchQuery("srcIP", ip);

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(ipQuery).withSearchType(SearchType.QUERY_AND_FETCH)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(QueryConstants.ALL_TYPES)
				.withSort(SortBuilders.fieldSort("dateTime").order(SortOrder.ASC)).withPageable(new PageRequest(0, 1)).build();
		JsonNode n = elasticsearchTemplate.query(searchQuery, new ResultsExtractor<JsonNode>() {

			@Override
			public JsonNode extract(SearchResponse response) {
				if (response.getHits() != null) {
					SearchHit hit = response.getHits().getAt(0);
					map.put("firstSeen", hit.getSource().get("dateTime"));
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

		ipNode = new ObjectMapper().convertValue(map, JsonNode.class);
		return ipNode;
	}
	
	public JsonNode getIPProbingAttempts(String ip, String to, String from){

		QueryBuilder ipQuery = QueryBuilders.matchQuery("srcIP", ip);
		
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
	
	public List<JsonNode> getIPActivityTimeline(String from, String to, String ip) {

		List<JsonNode> histogram = null;
		final HashMap<String, Object> map = new HashMap<String, Object>();
		QueryBuilder ipQuery = QueryBuilders.matchQuery("srcIP", ip);
		JsonNode duration = getIPActivityDuration(from, to, ip);
		
		String firstSeen = duration.get("firstSeen").asText();
		String lastSeen = duration.get("lastSeen").asText();
//		Duration dur = new Duration(firstSeen, end);
//		DateTime duration1 = new DateTime(lastSeen).minus(new DateTime(firstSeen));

		// build query
		searchQuery = new NativeSearchQueryBuilder().withQuery(ipQuery).withSearchType(SearchType.QUERY_AND_FETCH)
				.withIndices(QueryConstants.INCIDENT_INDEX).withTypes(QueryConstants.ALL_TYPES)
				.withSort(SortBuilders.fieldSort("dateTime").order(SortOrder.ASC)).withPageable(new PageRequest(0, 1)).build();
		JsonNode n = elasticsearchTemplate.query(searchQuery, new ResultsExtractor<JsonNode>() {

			@Override
			public JsonNode extract(SearchResponse response) {
				if (response.getHits() != null) {
					SearchHit hit = response.getHits().getAt(0);
					map.put("firstSeen", hit.getSource().get("dateTime"));
					map.put("Total Attacks", response.getHits().getTotalHits());
				}
				return new ObjectMapper().convertValue(map, JsonNode.class);

			}
		});
		return null;
	}

}
