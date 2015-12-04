/*
 * Copyright 2015 the original author or authors.
 * Copyright 2015 Sorcersoft.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sorcer.core.dispatch;

import org.codehaus.plexus.util.dag.CycleDetectedException;
import org.codehaus.plexus.util.dag.DAG;
import org.codehaus.plexus.util.dag.TopologicalSorter;
import org.codehaus.plexus.util.dag.Vertex;
import sorcer.co.operator;
import sorcer.co.tuple.SignatureEntry;
import sorcer.core.context.model.ent.Entry;
import sorcer.core.context.model.srv.Srv;
import sorcer.core.context.model.srv.SrvModel;
import sorcer.service.*;

import java.util.*;

import static sorcer.co.operator.ent;
import static sorcer.co.operator.paths;

/**
 * SORCER class
 * User: Pawel Rubach
 * Date: 23.11.2015
 *
 * Sort a list of entries in a model taking into account the dependencies
 */
public class SrvModelAutoDeps {

    private final DAG dag;
    private final Map entryMap;
    private final Map<String, String> entryToResultMap;
    private SrvModel srvModel;

    /**
     * Construct the SrvModelAutoDeps
     */
    public SrvModelAutoDeps(SrvModel srvModel) throws SortingException {

        dag = new DAG();
        entryMap = new HashMap();
        entryToResultMap = new HashMap<String, String>();
        this.srvModel = srvModel;

        addVertex(this.srvModel);

        try {
            getMapping(this.srvModel);
            List<String> sortedData = new ArrayList<String>();
            for (Iterator i = TopologicalSorter.sort(dag).iterator(); i.hasNext(); ) {
                sortedData.add((String) i.next());
            }
            addDependsOn(this.srvModel, Collections.unmodifiableList(sortedData));
        } catch (CycleDetectedException ce) {
            throw new SortingException(ce.getMessage());
        }
    }

    /**
     * Return the processed SrvModel
     * @return srvModel
     */
    public SrvModel get() {
        return srvModel;
    }

    /**
     * Add dependency information to the srvModel
     *
     * @param srvModel
     * @throws CycleDetectedException
     * @throws ContextException
     */
    private void addDependsOn(SrvModel srvModel, List<String> sortedEntries) {
        for (String entryName : sortedEntries) {
            // Only those that are entries in the srvModel
            if (!srvModel.getData().keySet().contains(entryName)) continue;
            Vertex vertex = dag.getVertex(entryName);
            if (vertex.getParentLabels() != null && vertex.getParentLabels().size() > 0) {
                List<String> paths = new ArrayList<String>();
                for (String dependent : vertex.getParentLabels()) {
                    if (entryToResultMap.containsKey(dependent)) {
                        Vertex depVertex = dag.getVertex(dependent);
                        if (depVertex.getParentLabels()!=null) {
                            for (String depInternal : depVertex.getParentLabels()) {
                                if (entryToResultMap.containsKey(depInternal)) {
                                    paths.add(entryToResultMap.get(depInternal));
                                }
                            }
                        }
                    }
                }
                if (paths.size()>0) operator.dependsOn(srvModel, ent(entryName, paths(paths.toArray(new String[0]))));
            }
        }
    }

    /**
     * Add SrvModel entries as Vertexes to the Directed Acyclic Graph (DAG)
     *
     * @param srvModel
     * @throws SortingException
     */
    private void addVertex(SrvModel srvModel) throws SortingException {

        for (String entryName : srvModel.getData().keySet()) {

            if (dag.getVertex(entryName) != null
                    && entryMap.get(entryMap)!=null
                    && (!srvModel.getData().get(entryName).equals(entryMap.get(entryMap)))) {
                        throw new SortingException("Entry named: '" + entryName +
                            " is duplicated in the model: '" + srvModel.getName() + "(" + srvModel.getId() + ")" +
                            "'\n" + entryName + "=" + entryMap.get(entryMap)
                            + "\n" + entryName + "=" + srvModel.getData().get(entryName));
            }

            dag.addVertex(entryName);
            entryMap.put(entryName, srvModel.getData().get(entryName));

            Object entry = srvModel.getData().get(entryName);
            if (entry instanceof Entry) {
                Object entryVal = ((Entry)entry)._2;
                Signature.ReturnPath rp = null;
                if (entryVal instanceof SignatureEntry) {
                    Signature signature = ((SignatureEntry)entryVal)._2;
                    if (signature!=null) rp = signature.getReturnPath();
                } else if (entry instanceof Srv) {
                    rp = ((Srv) entry).getReturnPath();
                }
                if (rp!=null) {
                    dag.addVertex(rp.getName());
                    entryToResultMap.put(rp.getName(), entryName);
                }


            }
            if (srvModel.getData().get(entryName) instanceof SrvModel) {
                addVertex((SrvModel)srvModel.getData().get(entryName));
            }
        }
    }

    /**
     * Find the dependencies that result from the paths in SignatureEntries for each entry that contains a task
     *
     * @param srvModel
     * @throws CycleDetectedException
     * @throws SortingException
     */
    private void getMapping(SrvModel srvModel) throws CycleDetectedException, SortingException {
        for (String entryName : srvModel.getData().keySet()) {
            Object entry = srvModel.getData().get(entryName);
            if (entry instanceof Entry) {
                Signature.ReturnPath rp = null;
                Object entryVal = ((Entry)entry)._2;
                if (entryVal instanceof SignatureEntry) {
                    Signature signature = ((SignatureEntry)entryVal)._2;
                    rp =  signature.getReturnPath();
                } else if (entry instanceof Srv) {
                    rp = ((Srv)entry).getReturnPath();
                }
                if (rp!=null) {
                    dag.addEdge(rp.getName(), entryName);
                    if (rp.inPaths != null) {
                        for (String inPath : rp.inPaths) {
                            dag.addEdge(inPath, rp.getName());
                        }
                    }
                }
            }
        }
    }
}
