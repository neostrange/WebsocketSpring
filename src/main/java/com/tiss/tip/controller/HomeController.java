package com.tiss.tip.controller;

import java.util.List;

import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.search.SearchType;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.search.sort.SortBuilders;
import org.elasticsearch.search.sort.SortOrder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.elasticsearch.core.ElasticsearchTemplate;
import org.springframework.data.elasticsearch.core.ResultsExtractor;
import org.springframework.data.elasticsearch.core.query.NativeSearchQueryBuilder;
import org.springframework.data.elasticsearch.core.query.SearchQuery;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.fasterxml.jackson.databind.JsonNode;
import com.tiss.tip.model.Incident;
import com.tiss.tip.model.MalwareIncident;
import com.tiss.tip.service.MalwareIncidentService;
import com.tiss.tip.service.NRTService;

/**
 * Handles requests for the application home page.
 */

@Controller
@RequestMapping("/")
public class HomeController {

	@Autowired
	public ElasticsearchTemplate elasticsearchTemplate;

	@Autowired
	private MalwareIncidentService malwareIncidentService;

	@Autowired
	private NRTService nrtService;

	private static final Logger logger = LoggerFactory.getLogger(HomeController.class);

	/**
	 * Simply selects the home view to render by returning its name.
	 */

	@RequestMapping(value = "/", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getIncidents(
			@RequestParam(required = false, defaultValue = "60") int interval) {
		logger.info("Start getIncidents");
		List<JsonNode> l = nrtService.getRecentIncidentActivity(interval);
		System.out.println(l.size());
		return l;
	}

	@RequestMapping(value = TipURIConstants.MALWARE_INCIDENT, method = RequestMethod.GET)
	public @ResponseBody List<MalwareIncident> getMalwareIncidents() {
		logger.info("Start getMalwareIncident");
		QueryBuilder builder = QueryBuilders.wrapperQuery("{ \"match_all\" : {}}");

		SearchQuery searchQuery = new NativeSearchQueryBuilder().withQuery(builder).build();
		List<MalwareIncident> incidents = elasticsearchTemplate.queryForList(searchQuery, MalwareIncident.class);
		return incidents;
	}

	@RequestMapping(value = "/recent/", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getRecentIncident() {
		logger.info("Start getMalwareIncident");
		QueryBuilder builder = QueryBuilders.wrapperQuery("{\"term\":{\"srcCountry\":\"China\"}}");

		SearchQuery searchQuery = new NativeSearchQueryBuilder().withQuery(builder).withIndices("incident")
				.withTypes("WebIncident", "SshIncident", "MalwareIncident").withSort(SortBuilders.fieldSort("dateTime"))
				.withPageable(new PageRequest(0, 100)).build();

		List<JsonNode> incidents = elasticsearchTemplate.queryForList(searchQuery, JsonNode.class);

		return incidents;
	}

	@RequestMapping(value = "/count/", method = RequestMethod.GET)
	public @ResponseBody Long getChinaIncidentCount() {
		logger.info("Start getMalwareIncident");
		QueryBuilder builder = QueryBuilders.wrapperQuery("{\"match\":{\"srcCountry\":\"China\"}}");

		SearchQuery searchQuery = new NativeSearchQueryBuilder().withQuery(builder)
				.withIndices("incident").withTypes("WebIncident", "SshIncident", "MalwareIncident",
						"NetworkLayerIncident", "SipIncident", "MssqlIncident", "MysqlIncident")
				.withSearchType(SearchType.COUNT).build();
		Long incidents = elasticsearchTemplate.query(searchQuery, new ResultsExtractor<Long>() {

			@Override
			public Long extract(SearchResponse response) {
				// TODO Auto-generated method stub
				return response.getHits().getTotalHits();
			}
		});
		return incidents;
	}

	@RequestMapping(value = "/counts", method = RequestMethod.GET)
	public @ResponseBody Long getIncidentCount(@RequestParam String field, @RequestParam String value) {
		logger.info("Start getMalwareIncident");
		QueryBuilder builder = QueryBuilders.wrapperQuery("{\"match\":{ \"" + field + "\": \"" + value + "\"}}");

		SearchQuery searchQuery = new NativeSearchQueryBuilder().withQuery(builder)
				.withIndices("incident").withTypes("WebIncident", "SshIncident", "MalwareIncident",
						"NetworkLayerIncident", "SipIncident", "MssqlIncident", "MysqlIncident")
				.withSearchType(SearchType.COUNT).build();
		Long incidents = elasticsearchTemplate.count(searchQuery);
		// System.out.println(incidents.size());
		return incidents;
	}

	@RequestMapping(value = "/counts/{type}", method = RequestMethod.GET)
	public @ResponseBody Long getIncidentCount(@RequestParam String field, @RequestParam String value,
			@PathVariable("type") String type) {
		logger.info("Start getMalwareIncident");
		QueryBuilder builder = QueryBuilders.wrapperQuery("{\"match\":{ \"" + field + "\": \"" + value + "\"}}");
		String[] a = null;
		SearchQuery searchQuery = new NativeSearchQueryBuilder().withQuery(builder).withIndices("incident").withTypes(a)
				.withSearchType(SearchType.COUNT).build();
		Long incidents = elasticsearchTemplate.count(searchQuery);
		return incidents;
	}

	@RequestMapping(value = "/malwareIncident/", method = RequestMethod.GET)
	public @ResponseBody MalwareIncident getMalwareIncident() {
		logger.info("Start getMalwareIncident");
		// simple comment.
		// return
		// malwareIncidentService.getByUrl("http://95.25.112.171:2830/uxgyw");
		return malwareIncidentService.getById("AVGlfVGnKMG7Pqq8lt-L");
	}

	@RequestMapping(value = "/try1/", method = RequestMethod.GET, produces = "application/json")
	public @ResponseBody String getMalwareBySrcIP() {
		logger.info("Get Malware By SrcIP");
		return malwareIncidentService.getBySrcIP("95.25.112.171");

	}

	@RequestMapping(value = "/recentIncidents/", method = RequestMethod.GET)
	public @ResponseBody Page<JsonNode> getRecentIncidents(@RequestParam(defaultValue = "0") int page) {
		logger.info("Start getRecentIncidents");
		QueryBuilder builder = QueryBuilders.wrapperQuery("{\"term\":{\"srcCountry\":\"China\"}}");

		SearchQuery searchQuery = new NativeSearchQueryBuilder().withQuery(builder).withIndices("incident")
				.withTypes("WebIncident", "SshIncident", "MalwareIncident")
				.withSort(SortBuilders.fieldSort("dateTime").order(SortOrder.DESC))
				.withPageable(new PageRequest(page, 1000)).build();

		Page<JsonNode> incidents = elasticsearchTemplate.queryForPage(searchQuery, JsonNode.class);

		return incidents;
	}

	@RequestMapping(value = "/sipIncidents/", method = RequestMethod.GET)
	public @ResponseBody Page<JsonNode> getSipIncidents(@RequestParam(defaultValue = "0") int page) {
		logger.info("Start getRecentIncidents");
		QueryBuilder builder = QueryBuilders.wrapperQuery("{\"term\":{\"origin.srcCountryCode\":\"USA\"}}");

		SearchQuery searchQuery = new NativeSearchQueryBuilder().withQuery(builder).withIndices("incident")
				.withTypes("SipIncident").withFields("origin.srcCountry")
				.withSort(SortBuilders.fieldSort("dateTime").order(SortOrder.DESC))
				.withPageable(new PageRequest(page, 10000)).build();

		Page<JsonNode> incidents = elasticsearchTemplate.queryForPage(searchQuery, JsonNode.class);

		return incidents;
	}

	@RequestMapping(value = "/minc/", method = RequestMethod.GET)
	public @ResponseBody List<Incident> getMIncidents(@RequestParam String dip) {
		logger.info("Start getIncidents");
		List<Incident> l = malwareIncidentService.getByDstIP(dip);
		System.out.println(l.size());
		return l;
	}

}
