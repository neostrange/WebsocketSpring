package com.tiss.tip.controller;

import java.text.DateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;


import org.elasticsearch.common.geo.GeoPoint;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.index.query.BoolQueryBuilder;
import static org.elasticsearch.index.query.QueryBuilders.nestedQuery;
import static org.elasticsearch.index.query.QueryBuilders.termQuery;
import static org.elasticsearch.index.query.QueryBuilders.boolQuery;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.elasticsearch.core.ElasticsearchTemplate;
import org.springframework.data.elasticsearch.core.query.NativeSearchQueryBuilder;
import org.springframework.data.elasticsearch.core.query.SearchQuery;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.tiss.tip.model.Incident;
import com.tiss.tip.model.MalwareIncident;
import com.tiss.tip.model.Origin;
import com.tiss.tip.service.MalwareIncidentService;

/**
 * Handles requests for the application home page.
 */


@Controller
public class HomeController {
	
	@Autowired
	private ElasticsearchTemplate elasticsearchTemplate;
	
	
	@Autowired
	private MalwareIncidentService malwareIncidentService;
	
	

	private static final Logger logger = LoggerFactory.getLogger(HomeController.class);

	/**
	 * Simply selects the home view to render by returning its name.
	 */
	@RequestMapping(value = "/", method = RequestMethod.GET)
	public String home(Locale locale, Model model) {
		logger.info("Welcome home! The client locale is {}.", locale);

		Date date = new Date();
		DateFormat dateFormat = DateFormat.getDateTimeInstance(DateFormat.LONG, DateFormat.LONG, locale);

		String formattedDate = dateFormat.format(date);

		model.addAttribute("serverTime", formattedDate);

		return "home";
	}

	@RequestMapping(value = TipURIConstants.DUMMY_INCIDENT, method = RequestMethod.GET)
	public @ResponseBody Incident getDummyIncident() {
		logger.info("Start getDummyEmployee");
		Incident incident = new Incident();
		incident.setDateTime("11-DEC-2015");
		incident.setDestinationIP("127.0.0.1");
		incident.setDstPort(8333);
		incident.setProtocol("HTTP");
		incident.setService("WEB");
		incident.setSourcePort(3223);
		incident.setSrcIP("0.0.0.0");
		incident.setOrigin(new Origin("pakistan","123","rwp",new GeoPoint(2244.00,4534.00)));
		return incident;
	}
	
	
	@RequestMapping(value = TipURIConstants.MALWARE_INCIDENT, method = RequestMethod.GET)
	public @ResponseBody List<MalwareIncident> getMalwareIncidents() {
		logger.info("Start getMalwareIncident");
		 QueryBuilder builder =QueryBuilders.matchAllQuery();
		
		    SearchQuery searchQuery = new NativeSearchQueryBuilder().withQuery(builder).build();
		    List<MalwareIncident> incidents = elasticsearchTemplate.queryForList(searchQuery, MalwareIncident.class);
		return incidents;
	}
	
	
	@RequestMapping(value = "/malwareIncident/", method = RequestMethod.GET)
	public @ResponseBody MalwareIncident getMalwareIncident() {
		logger.info("Start getMalwareIncident");
		 //simple comment.
		//return malwareIncidentService.getByUrl("http://95.25.112.171:2830/uxgyw");
		return malwareIncidentService.getById("AVGlfVGnKMG7Pqq8lt-L");
	}

}
