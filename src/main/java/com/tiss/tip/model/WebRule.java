package com.tiss.tip.model;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * Singleton for describing the Modsecurity rule triggered by the
 * {@code WebIncident}.
 */
public class WebRule {

	/**
	 * The logger for this class.
	 */
	private static Logger log = LoggerFactory.getLogger(WebRule.class);

	/**
	 * Category of the triggered rule.
	 */
	private String ruleCategory;
	/**
	 * Message of the triggered rule.
	 */
	private String ruleMessage;

	/**
	 * Default Constructor
	 */
	public WebRule() {
	}

	/**
	 * Instantiates a new{@link WebRule}.
	 *
	 * @param ruleCategory
	 *            the rule category
	 * @param ruleMessage
	 *            the rule message
	 */
	public WebRule(String ruleCategory, String ruleMessage) {
		super();
		log.trace("Create new WebRule where ruleMessage [{}]", ruleMessage);
		this.ruleCategory = ruleCategory;
		this.ruleMessage = ruleMessage;
	}

	
	/**
	 * Gets the category of the triggered rule.
	 *
	 * @return the category of the triggered rule
	 */
	public String getRuleCategory() {
		log.trace("Get ruleCategory, returns [{}]", ruleCategory);
		return ruleCategory;
	}

	/**
	 * Sets the category of the triggered rule.
	 *
	 * @param ruleCategory
	 *            the new category of the triggered rule
	 */
	public void setRuleCategory(String ruleCategory) {
		log.trace("Set ruleCategory to [{}]", ruleCategory);
		this.ruleCategory = ruleCategory;
	}

	/**
	 * Gets the message of the triggered rule.
	 *
	 * @return the message of the triggered rule
	 */
	public String getRuleMessage() {
		log.trace("Get ruleMessage, returns [{}]", ruleMessage);
		return ruleMessage;
	}

	/**
	 * Sets the message of the triggered rule.
	 *
	 * @param ruleMessage
	 *            the new message of the triggered rule
	 */
	public void setRuleMessage(String ruleMessage) {
		log.trace("Set ruleMessage to [{}]", ruleMessage);
		this.ruleMessage = ruleMessage;
	}

}