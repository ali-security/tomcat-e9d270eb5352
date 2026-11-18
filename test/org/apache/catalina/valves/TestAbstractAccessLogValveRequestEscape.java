/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.valves;

import java.io.CharArrayWriter;
import java.util.Date;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Request;
import org.apache.catalina.valves.AbstractAccessLogValve.AccessLogElement;
import org.apache.tomcat.util.json.JSONParser;

/**
 * The request URI and the query string are only guaranteed to be free of
 * characters such as {@code "} and {@code \} while the connector is using the
 * default {@code relaxedPathChars} / {@code relaxedQueryChars}. Once those are
 * relaxed, those characters reach the access log and - unless they are escaped
 * - allow arbitrary content to be injected into the log. This is particularly
 * harmful for JSON formatted access logs where it allows additional fields to
 * be injected into the log record.
 */
public class TestAbstractAccessLogValveRequestEscape {

    /*
     * A request URI that closes the JSON string it is written into and then
     * adds an additional field to the JSON access log record.
     */
    private static final String URI_RAW = "/app/x\",\"injected\":\"yes";
    private static final String URI_ESCAPED = "/app/x\\\",\\\"injected\\\":\\\"yes";

    /*
     * A query string that combines the same JSON injection with a backslash
     * and a line break.
     */
    private static final String QUERY_RAW = "p=1\",\"evil\":\"2\\\nq=3";
    private static final String QUERY_ESCAPED = "p=1\\\",\\\"evil\\\":\\\"2\\\\\\nq=3";


    private static Request createRequest(String uri, String query) {
        org.apache.coyote.Request coyoteRequest = new org.apache.coyote.Request();
        coyoteRequest.method().setString("GET");
        coyoteRequest.protocol().setString("HTTP/1.1");
        if (uri != null) {
            coyoteRequest.requestURI().setString(uri);
        }
        if (query != null) {
            coyoteRequest.queryString().setString(query);
        }

        Request request = new Request((Connector) null);
        request.setCoyoteRequest(coyoteRequest);
        return request;
    }


    private static String format(AccessLogElement element, Request request) {
        CharArrayWriter buf = new CharArrayWriter();
        element.addElement(buf, new Date(), request, null, 0);
        return buf.toString();
    }


    /**
     * %U - the request URI must be escaped.
     */
    @Test
    public void testRequestURIElement() {
        Request request = createRequest(URI_RAW, QUERY_RAW);
        Assert.assertEquals(URI_ESCAPED,
                format(new AbstractAccessLogValve.RequestURIElement(), request));
    }


    /**
     * %U - control characters and characters outside of US-ASCII in the
     * request URI must be escaped.
     */
    @Test
    public void testRequestURIElementControlAndNonAscii() {
        Request request = createRequest("/a\r\nb\t\u0001\u007f\u00e9", null);
        Assert.assertEquals("/a\\r\\nb\\t\\u0001\\u007f\\u00e9",
                format(new AbstractAccessLogValve.RequestURIElement(), request));
    }


    /**
     * %q - the query string must be escaped.
     */
    @Test
    public void testQueryElement() {
        Request request = createRequest(URI_RAW, QUERY_RAW);
        Assert.assertEquals("?" + QUERY_ESCAPED,
                format(new AbstractAccessLogValve.QueryElement(), request));
    }


    /**
     * %q - a present but empty query string must be logged as "?", not "?-".
     */
    @Test
    public void testQueryElementEmptyQuery() {
        Request request = createRequest("/app", "");
        Assert.assertEquals("?",
                format(new AbstractAccessLogValve.QueryElement(), request));
    }


    /**
     * %q - no query string means nothing is logged.
     */
    @Test
    public void testQueryElementNoQuery() {
        Request request = createRequest("/app", null);
        Assert.assertEquals("",
                format(new AbstractAccessLogValve.QueryElement(), request));
    }


    /**
     * %r - both the request URI and the query string must be escaped.
     */
    @Test
    public void testRequestElement() {
        Request request = createRequest(URI_RAW, QUERY_RAW);
        Assert.assertEquals("GET " + URI_ESCAPED + "?" + QUERY_ESCAPED + " HTTP/1.1",
                format(new AbstractAccessLogValve.RequestElement(), request));
    }


    /**
     * %r - a present but empty query string must be logged as "?", not "?-".
     */
    @Test
    public void testRequestElementEmptyQuery() {
        Request request = createRequest("/app", "");
        Assert.assertEquals("GET /app? HTTP/1.1",
                format(new AbstractAccessLogValve.RequestElement(), request));
    }


    /**
     * %r - no query string means no "?" is logged.
     */
    @Test
    public void testRequestElementNoQuery() {
        Request request = createRequest("/app", null);
        Assert.assertEquals("GET /app HTTP/1.1",
                format(new AbstractAccessLogValve.RequestElement(), request));
    }


    /**
     * The same elements, obtained the way a configured valve obtains them.
     */
    @Test
    public void testRequestElementViaPattern() {
        AbstractAccessLogValve valve = new AbstractAccessLogValve() {
            @Override
            protected void log(CharArrayWriter message) {
                // NO-OP
            }
        };
        valve.setPattern("\"%r\" \"%U\" \"%q\"");

        Request request = createRequest(URI_RAW, QUERY_RAW);
        CharArrayWriter buf = new CharArrayWriter();
        for (AccessLogElement element : valve.createLogElements()) {
            element.addElement(buf, new Date(), request, null, 0);
        }

        Assert.assertEquals("\"GET " + URI_ESCAPED + "?" + QUERY_ESCAPED + " HTTP/1.1\" \"" +
                URI_ESCAPED + "\" \"?" + QUERY_ESCAPED + "\"",
                buf.toString());
    }


    private static String buildJsonRecord(String key, AccessLogElement element, Request request) {
        CharArrayWriter buf = new CharArrayWriter();
        buf.append("{\"");
        buf.append(key);
        buf.append("\":\"");
        element.addElement(buf, new Date(), request, null, 0);
        buf.append("\",\"status\":\"200\"}");
        return buf.toString();
    }


    /**
     * Build a JSON access log record the way a JSON formatted access log does
     * and confirm the request URI cannot inject an additional field into it.
     */
    @Test
    public void testJsonAccessLogUriFieldInjection() throws Exception {
        Request request = createRequest(URI_RAW, null);
        String json = buildJsonRecord("path", new AbstractAccessLogValve.RequestURIElement(), request);

        Map<String,Object> record = new JSONParser(json).parseObject();

        // No additional field may have been injected
        Assert.assertEquals(json, 2, record.size());
        Assert.assertFalse(json, record.containsKey("injected"));
        Assert.assertEquals(json, "200", record.get("status"));

        // The value must still be present, escaped. Note that JSONParser
        // returns the string content as written, it does not process the
        // escape sequences.
        Assert.assertEquals(json, URI_ESCAPED, record.get("path"));
    }


    /**
     * As above for the query string which, additionally, must not be able to
     * break the JSON access log record with a backslash or a line break.
     */
    @Test
    public void testJsonAccessLogQueryFieldInjection() throws Exception {
        Request request = createRequest(URI_RAW, QUERY_RAW);
        String json = buildJsonRecord("query", new AbstractAccessLogValve.QueryElement(), request);

        // A single line
        Assert.assertEquals(json, -1, json.indexOf('\n'));

        Map<String,Object> record = new JSONParser(json).parseObject();

        Assert.assertEquals(json, 2, record.size());
        Assert.assertFalse(json, record.containsKey("evil"));
        Assert.assertEquals(json, "200", record.get("status"));
        Assert.assertEquals(json, "?" + QUERY_ESCAPED, record.get("query"));
    }


    /**
     * As above for the request line.
     */
    @Test
    public void testJsonAccessLogRequestFieldInjection() throws Exception {
        Request request = createRequest(URI_RAW, QUERY_RAW);
        String json = buildJsonRecord("request", new AbstractAccessLogValve.RequestElement(), request);

        // A single line
        Assert.assertEquals(json, -1, json.indexOf('\n'));

        Map<String,Object> record = new JSONParser(json).parseObject();

        Assert.assertEquals(json, 2, record.size());
        Assert.assertFalse(json, record.containsKey("injected"));
        Assert.assertFalse(json, record.containsKey("evil"));
        Assert.assertEquals(json, "200", record.get("status"));
        Assert.assertEquals(json, "GET " + URI_ESCAPED + "?" + QUERY_ESCAPED + " HTTP/1.1",
                record.get("request"));
    }
}
