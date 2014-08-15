/**
 * Copyright (c) 2002-2014, OnPoint Digital, Inc. All rights reserved
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package org.jsoup.safety;

import org.jsoup.helper.Validate;

import java.util.*;

/**
 The {@code Feature} class defines html features that can be added to a whitelist using the {@link Whitelist#addFeature}
 method.

 @author Alex Westphal
 */
public class Feature {

    protected final List<String> tags = new ArrayList<String>();
    protected final Map<String, List<String>> attributes = new HashMap<String, List<String>>();
    protected final Map<String, Map<String, String>> enforced = new HashMap<String, Map<String, String>>();
    protected final Map<String, Map<String, List<String>>> protocols = new HashMap<String, Map<String, List<String>>>();

    protected Feature() {}

    /**
     Add a list of allowed elements to a feature.

     @param tags tag names to allow
     @return this (for chaining)
     */
    protected Feature addTags(String... tags) {
        Validate.notNull(tags);
        Collections.addAll(this.tags, tags);
        return this;
    }

    /**
     Add a list of allowed attributes to a tag.

     @param tag  The tag the attributes are for.
     @param keys List of valid attributes for the tag
     @return this (for chaining)
     */
    protected Feature addAttributes(String tag, String... keys) {
        Validate.notEmpty(tag);
        Validate.notNull(keys);

        List<String> attrs;
        if(attributes.containsKey(tag))
            attrs = attributes.get(tag);
        else
            attributes.put(tag, attrs = new ArrayList<String>());
        Collections.addAll(attrs, keys);
        return this;
    }

    /**
     Add an enforced attribute to a tag.


     @param tag   The tag the enforced attribute is for.
     @param key   The attribute key
     @param value The enforced attribute value
     @return this (for chaining)
     */
    protected Feature addEnforcedAttribute(String tag, String key, String value) {
        Validate.notEmpty(tag);
        Validate.notEmpty(key);
        Validate.notEmpty(value);

        Map<String, String> attrs;
        if(enforced.containsKey(tag))
            attrs = enforced.get(key);
        else
            enforced.put(tag, attrs = new HashMap<String, String>());
        attrs.put(key, value);
        return this;
    }

    /**
     Add allowed URL protocols for an element's URL attribute. This restricts the possible values of the attribute to
     URLs with the defined protocol.

     @param tag       Tag the URL protocol is for
     @param key       Attribute key
     @param protocols List of valid protocols
     @return this, for chaining
     */
    protected Feature addProtocols(String tag, String key, String... protocols) {
        Validate.notEmpty(tag);
        Validate.notEmpty(key);
        Validate.notNull(protocols);

        Map<String, List<String>> attrs;
        if(this.protocols.containsKey(tag))
            attrs = this.protocols.get(tag);
        else
            this.protocols.put(tag, attrs = new HashMap<String, List<String>>());

        List<String> prots;
        if(attrs.containsKey(key))
            prots = attrs.get(key);
        else
            attrs.put(key, prots = new ArrayList<String>());
        Collections.addAll(prots, protocols);
        return this;
    }

    /**
     This feature allows style tags, as well as class and style attributes on all tags. It should be used with extreme
     caution as no validation of the CSS is performed. See http://ha.ckers.org/xss.html for some examples of XSS attacks
     using CSS.

     @return feature
     */
    public static Feature css() {
        return new Feature()
                .addTags("style")
                .addAttributes(":all", "class", "style");
    }

    /**
     This feature allows the tags required for a full HTML document: {@code body, head, html, meta, title}, and
     appropriate attributes.

     @return feature
     */
    public static Feature document() {
        return new Feature()
                .addTags("body", "head", "html", "meta", "title")
                .addAttributes("meta", "charset", "content", "http-equiv", "name")
                ;
    }

    /**
     This feature allows links ({@code a} elements) that can point to {@code http, https, ftp, mailto}, and have an
     enforced {@code rel=nofollow} attribute.

     @return feature
     */
    public static Feature links() {
        return new Feature()
                .addTags("a")
                .addAttributes("a", "href")
                .addProtocols("a", "href", "ftp", "http", "https", "mailto")
                .addEnforcedAttribute("a", "rel", "nofollow")
                ;
    }

    /**
     This feature allows tables, associated sub tags {@code tbody, td, tfoot, th, thead, tr}, and appropriate
     attributes.

     @return feature
     */
    public static Feature tables() {
        return new Feature()
                .addTags("table", "tbody", "td", "tfoot", "th", "thead", "tr")
                .addAttributes("td", "colspan", "headers", "rowspan")
                .addAttributes("th", "colspan", "headers", "rowspan", "scope", "sorted")
                ;

    }
}
