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

import java.util.List;
import java.util.Map;

/**
 The {@code Feature} class defines html features that can be added to a whitelist using the {@link Whitelist#addFeature}
 method.

 @author Alex Westphal
 */
public class Feature {

    protected final List<String> tags;
    protected final Map<String, List<String>> attributes;
    protected final Map<String, Map<String, String>> enforced;
    protected final Map<String, Map<String, List<String>>> protocols;


    public Feature(List<String> tags, Map<String, List<String>> attributes, Map<String, Map<String, String>> enforced,
                   Map<String, Map<String, List<String>>> protocols) {
        this.tags = tags;
        this.attributes = attributes;
        this.enforced = enforced;
        this.protocols = protocols;
    }
}
