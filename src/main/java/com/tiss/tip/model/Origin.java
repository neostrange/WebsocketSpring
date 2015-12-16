package com.tiss.tip.model;

import org.elasticsearch.common.geo.GeoPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.elasticsearch.annotations.Field;
import org.springframework.data.elasticsearch.annotations.FieldType;

// TODO: Auto-generated Javadoc
/**
 * Information about the origin of the attack, and its geolocation information.
 */
public class Origin {

	/**
	 * The logger for this class.
	 */
	private static Logger log = LoggerFactory.getLogger(Origin.class);


	/**
	 * The country from where the attack originated.
	 */
	private String srcCountry;
	/**
	 * The country code from where the attack originated.
	 */
	private String srcCountryCode;
	/**
	 * The city from where the attack originated.
	 */
	private String city;
	/**
	 * The geolocation information regarding the sourceIP.
	 */
	@Field (type = FieldType.Object)
	private GeoPoint geoPoint;

	/**
	 * Instantiates a new {@link Origin}.
	 *
	 * @param srcCountry
	 *            the src country
	 * @param srcCountryCode
	 *            the src country code
	 * @param city
	 *            the city
	 * @param geoPoint
	 *            the geo point {@link GeoPoint}
	 */
	public Origin(String srcCountry, String srcCountryCode, String city, GeoPoint geoPoint) {
		super();
		log.trace("Create new Origin instance where srcCountry [{}], srcCountryCode [{}]", srcCountry, srcCountryCode);
		this.srcCountry = srcCountry;
		this.srcCountryCode = srcCountryCode;
		this.city = city;
		this.geoPoint = geoPoint;
	}
	
	
	
	
	public Origin() {
		super();
	}




	/**
	 * Gets the country from where the attack originated.
	 *
	 * @return the country from where the attack originated
	 */
	public String getSrcCountry() {
		log.trace("Get srcCountry, returns [{}]", srcCountry);
		return srcCountry;
	}

	/**
	 * Sets the country from where the attack originated.
	 *
	 * @param srcCountry
	 *            the new country from where the attack originated
	 */
	public void setSrcCountry(String srcCountry) {
		log.trace("Set srcCountry to [{}]", srcCountry);
		this.srcCountry = srcCountry;
	}

	/**
	 * Gets the country code from where the attack originated.
	 *
	 * @return the country code from where the attack originated
	 */
	public String getSrcCountryCode() {
		log.trace("Get srcCountryCode, returns [{}]", srcCountryCode);
		return srcCountryCode;
	}

	/**
	 * Sets the country code from where the attack originated.
	 *
	 * @param srcCountryCode
	 *            the new country code from where the attack originated
	 */
	public void setSrcCountryCode(String srcCountryCode) {
		log.trace("Set srcCountryCode to [{}]", srcCountryCode);
		this.srcCountryCode = srcCountryCode;
	}

	/**
	 * Gets the city from where the attack originated.
	 *
	 * @return the city from where the attack originated
	 */
	public String getCity() {
		log.trace("Get city, returns [{}]", city);
		return city;
	}

	/**
	 * Sets the city from where the attack originated.
	 *
	 * @param city
	 *            the new city from where the attack originated
	 */
	public void setCity(String city) {
		log.trace("Set city to [{}]", city);
		this.city = city;
	}

	/**
	 * Gets the geolocation information regarding the source IP.
	 *
	 * @return the geolocation information regarding the source IP
	 */
	public GeoPoint getGeoPoint() {
		log.trace("Get geoPoint, returns GeoPoint with lat [{}], lon [{}]", geoPoint.lat(), geoPoint.lon());
		return geoPoint;
	}

	/**
	 * Sets the geolocation information regarding the source IP.
	 *
	 * @param geolocation
	 *            the new geolocation information regarding the source IP
	 */
	public void setGeoPoint(GeoPoint geolocation) {
		log.trace("Set geoPoint to lat [{}], lon [{}]", geolocation.lat(), geolocation.lon());
		this.geoPoint = geolocation;
	}

}
