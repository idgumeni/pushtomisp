import pymisp
import logging
from pprint import pprint




class MISP_DATA:

    ontology_result={}
    submission_result=[]
    misp_objects = []
    evt_attributes = []
    evt_tags=[]
   
    event = pymisp.MISPEvent()
    resp_event = {}
    #ontological_results_types=['antivirus','malwareconfig','netflow','process','sandbox','signature','heuristics','tags']
    object_name_fields = ['filename']
    
    al2misp_mappings={ #AL:MISP
        'objects':{
            'file':{'to':'file',
                    'names': {'action':'map', 'params':{'type': 'filename', 'object_relation': 'filename', 'to_ids':False}},
                    'md5': {'action':'map', 'params':{ 'type': 'md5', 'object_relation': 'md5', 'to_ids':False}},
                    "sha1":{'action':'map', 'params':{ 'type': 'sha1', 'object_relation': 'sha1', 'to_ids':False}},
                    "sha256":{'action':'map', 'params':{ 'type': 'sha256', 'object_relation': 'sha256', 'to_ids':False}},
                    "size":{'action':'map', 'params': { 'type': 'size-in-bytes', 'object_relation': 'size-in-bytes', 'to_ids':False}},
                    "type":{'action':'map', 'params': { 'type': 'mime-type', 'object_relation': 'mimetype', 'to_ids':False}},
                    "parent":{'action':'add_reference', 'params':{ 'type': 'child-of', 'relationship_type': 'child-of', 'to_ids':False}},
                    "pe/imphash":{'action':'map', 'params': { 'type': 'imphash', 'object_relation': 'imphash', 'to_ids':False}},
            },

        },
        'events':{
            'attributes':{
                "network.static.domain":{'action':'map', 'ref':'communicates-with', 'params':{ 'type': 'domain', "to_ids": True}},
                "network.static.uri": {'action':'map', 'ref':'communicates-with', 'params':{ 'type': "uri", "to_ids": True}},
                "file.string.blacklisted":{'action':'map', 'ref':'capability', 'params':{ 'type': "text", "to_ids": False}},
                "network.static.uri_path":{'action':'map', 'ref':'communicates-with', 'params':{ 'type': "text", "to_ids": False}},
                "network.dynamic.domain":{'action':'map', 'ref':'communicates-with', 'params':{ 'type': 'domain', "to_ids": True}},
                "network.dynamic.uri": {'action':'map', 'ref':'communicates-with', 'params':{ 'type': "uri", "to_ids": True}},
                "network.dynamic.uri_path":{'action':'map', 'ref':'communicates-with', 'params':{ 'type': "text", "to_ids": False}},
            }
        }

    }


    def __init__(self, url, apikey, content_type, **default_data):
        try:
            self.misp = pymisp.PyMISP(url, apikey, False, False)
            logging.warning("Misp connection created.")
        except Exception as e:
            print("Error creating misp connection:", e)
        self.tool_name=default_data['tool_name']
        self.analysis=default_data['analysis']
        self.threat_level_id=default_data['threat_level_id']
        self.distribution=default_data['distribution']
        self.content_type=content_type

    def findFileObjectBySha256(self,sha256):
        # Search for MISP events containing objects with the specified SHA256
        misp_objs=[]
        try:
            #search in current MISPObjects from self.misp_objects
            for obj_item in self.misp_objects:
              for obj_attr in obj_item.to_dict().get('Attribute'):
                obj_dict = obj_attr.to_dict()
                if (obj_dict['object_relation'] == 'sha256') and  ( obj_dict['value'] == sha256 ):
                    misp_objs.append(obj_item['uuid'])
                    break
        except Exception as e:
            print("error finding objects:", e)
        return misp_objs


    def recursiveIteration(self,mixeddata,prefix=''):
        if isinstance(mixeddata,list) and (prefix == ''):
            for dataitem in mixeddata:
                yield from self.recursiveIteration(dataitem)
        elif isinstance(mixeddata,dict):
            try:
                for k,v in mixeddata.items():
                    if isinstance(v,dict) or isinstance(v,list):  
                        yield from self.recursiveIteration(v,prefix + k + '/')
                    else:
                        yield  prefix + k ,v    
            except Exception as e:
                print("Error recursiveIteration:", e)
        elif ( (not prefix == '') and (isinstance(mixeddata,list)) ):
            try:
                for v in mixeddata:
                    if isinstance(v,dict) or isinstance(v,list):  
                        yield from self.recursiveIteration(v,prefix )
                    else:
                        yield  prefix.rstrip('/'), v   
            except Exception as e:
                print("Error recursiveIteration - list:", e)


    def createAttributesDict2(self,attr_scope,al_attr_type, data):
        attributes=[]
        references=[]
        
        try:
            for k,v in self.recursiveIteration(data):
                print("... in createAttributesDict2 - %s - k:%s -> v:%s" %(attr_scope,k,v))
                if k in self.al2misp_mappings[attr_scope][al_attr_type]:
                    if self.al2misp_mappings[attr_scope][al_attr_type][k]['action'] == 'map':
                        print("#### createObjectAttributes list: to: ",self.al2misp_mappings[attr_scope][al_attr_type][k]['params'])
                        print("#### createObjectAttributes: atributes: %s: %s" % (k,v))
                        attributes.append(dict({'value':v, **self.al2misp_mappings[attr_scope][al_attr_type][k]['params']}))
                    elif self.al2misp_mappings[attr_scope][al_attr_type][k]['action'] == 'add_reference':
                        references.append(dict({'referenced_uuid':v}, **self.al2misp_mappings[attr_scope][al_attr_type][k]['params']))
                        print("#### createObjectAttributes: references: %s: %s" % (k,v))
        except Exception as e:
            print("Error createAttributesDict2:",e)
        return [attributes,references]

     
    def createAttribute(self,attr_dict):
        attribute = pymisp.MISPAttribute()
        print ("createAttribute attr_dict: ", attr_dict)
        try:
            attribute.from_dict(**attr_dict)
            print("createAttribute attribute created: ", attribute)
        except Exception as e:
            print(" createAttribute  Error creating attribute: ", e)
        return attribute


    def createObject(self, attrs_object_dict):
        #, refs_objects_list
        try:
            misp_object=pymisp.MISPObject('file')
        except Exception as e:
            print("Error creating misp obj:",e)
        try:
            for atrib_item in attrs_object_dict:
                ret_attr=misp_object.add_attribute( **atrib_item)
        except Exception as e:
            print("Error - createObject - adding attribute to object:", e)
        
        return misp_object
            
            
    def createFileObjects(self):
        f_objects=[]
        f_objects_data={}
        f_objects_data['attrs_object_dicts']=[]
        f_objects_data['refs_objects_list']=[]
        
        for ontology_item in self.ontology_result:
            [attrs_object_dict,refs_objects_list]=self.createAttributesDict2('objects','file', ontology_item['file'])
            #check for duplicates objects in ontology
            if attrs_object_dict not in f_objects_data['attrs_object_dicts']:
                f_objects_data['attrs_object_dicts'].append(attrs_object_dict)
                f_objects_data['refs_objects_list'].append(refs_objects_list)
            
                obj_item=self.createObject(attrs_object_dict)
                f_objects.append(obj_item)
                self.misp_objects = f_objects
                #add references
                for obj_reference in refs_objects_list:
                    references=self.findFileObjectBySha256(obj_reference['referenced_uuid'])
                    try:
                        for reference_item in references:
                            ref_ret=obj_item.add_reference(reference_item, obj_reference['relationship_type'])
                    except Exception as e:
                        print("Error  createObjectDict No references found", e)

        return f_objects


    def createEventAttributes(self,evt_attrs_dict):
        evt_attr_objects=[]
        for attr_item in evt_attrs_dict:
            try:
                evt_attr_objects.append(self.createAttribute(attr_item))
            except Exception as e:
                print('Error createAttribute error creating attribute: ', e)
        
        return evt_attr_objects
        

    def createEventAttributesDict(self):
        o_data_item={}
        event_attrs=[]
        for ontology_item in self.ontology_result:
            tag2add=ontology_item['service'].get('name')
            try:
                result_items=ontology_item['results'].items()
            except Exception as e:
                print("Error iterating through result items:", e)
                break;
        
            for result_ontology_k,result_ontology_v in result_items:
                try:
                    [attrs,refs]=self.createAttributesDict2('events','attributes', result_ontology_v)
                    if len(attrs) > 0:
                        self.evt_tags.append(dict({'name':'detection:'+tag2add}))
                    event_attrs = event_attrs + attrs
                except Exception as e:
                    print("Error in createAttributesDict2 - error:", e)
        logging.warning("misp createObject: ok")
        return event_attrs
        

    def createTags(self):
        ret_tags=[]
        for tag_item in self.evt_tags:
            try:
                tagobj=pymisp.MISPTag()
                tagobj.from_dict(**tag_item)
                ret_tags.append(tagobj)
            except Exception as e:
                print("Error createTags  error adding tag: " , tag_item , " error: ", e)

        return ret_tags

    def addTags2Event(self):
        tag2add=dict({'name':self.tool_name})
        if tag2add not in self.evt_tags:
            self.evt_tags.append( tag2add ) 
        tags=self.createTags()
        for tag in tags:
            try:
                ret_new_tag=self.misp.add_tag(tag) 
                ret_add_tag2evt=self.event.add_tag(str(tag.to_dict()['name']))
            except Exception as e:
                print("err addTags2Event  add tag ::: " , e)
            
           
        
        
    def createEvent(self,**submission_attrs):
        
        # date, threat_level, Distribution, analysis, info, extends
        self.event.info = submission_attrs['info']
        self.event.threat_level_id = self.threat_level_id
        self.event.distribution = self.distribution
        self.event.analysis = self.analysis
        self.evt_tags.append(dict({'name':'classification:' + submission_attrs['classification']}))
        evt_attrs_dict=self.createEventAttributesDict()
        evt_attrs=self.createEventAttributes(evt_attrs_dict)
        for attr in evt_attrs:
            self.event.add_attribute(**attr)

        try:
            for obj_item in self.misp_objects:
                ret_add_obj=self.event.add_object(obj_item)
        except Exception as e:
            print('Error - createEvent - adding object to event : ',e)
        
        #add tags to event
        try:
            self.addTags2Event()
        except Exception as e:
            print("Error add tags: ", e)

        # Add the event to MISP
        try:
            self.resp_event = self.misp.add_event(self.event)
        except Exception as e:
            print("Error creating event: ", e)

    
        #self.event.publish()
        logging.warning("Event info:" + self.event.info)


