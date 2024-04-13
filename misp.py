import pymisp
import logging
from pprint import pprint
import urllib.parse

# MISPEvent
# load_file(event_path)
# load(json_event)
# add_attribute(type, value, **kwargs)
# add_object(obj=None, **kwargs)
# add_attribute_tag(tag, attribute_identifier)
# get_attribute_tag(attribute_iden
# add_tag(tag=None, **kwargs)

# MISPObject
# add_attribute(object_relation, **value)
# add_reference(referenced_uuid, relationship_type,
# comment=None, **kwargs)
# has_attributes_by_relation(list_of_relations)
# get_attributes_by_relation(object_relation)
# attributes[], relations[]
# edited, all other paramaters of the MISPObject element
# (name, comment, ...)

# MISPAttribute
# add_tag(tag=None, **kwargs)
# delete()
# malware_binary (if relevant)
# tags[]

# self.attribute = {'to_ids': True}
# misp_event.add_tag(submission['classification'].lower())

# create file object ( file_object = MISPObject('file'))
#     add attribute to file object (file_object.add_attribute(value=file_info[feature], **attribute))
# add references to file object  (from mapping fields ) 
# add object to Event 




class MISP_DATA:
    threat_level = 4
    analysis = 0
    content_type = "json"
    ontology_result={}
    submission_result=[]
    misp_objects = []
    evt_attributes = []
    event = pymisp.MISPEvent()
    resp_event = {}
    ontological_results_types=['antivirus','malwareconfig','netflow','process','sandbox','signature','heuristics']
    al2misp_mappings={ #AL:MISP
        'objects':{
            'file':{'mapto':'file',
                    'names': {'action':'map', 'mapto': 'filename'},
                    'md5': {'action':'map', 'mapto': 'md5'},
                    "sha1":{'action':'map', 'mapto': 'sha1'},
                    "sha256":{'action':'map', 'mapto': 'sha256'},
                    "size":{'action':'map', 'mapto': 'size-in-bytes'},
                    "type":{'action':'map', 'mapto': 'mime-type'},
                    "parent":{'action':'add_reference', 'mapto': 'child-of'},
            },

        },
        'events':{
            'attributes':{
                "network.static.domain":{'action':'map', 'mapto': 'domain', "to_ids": True, 'add_tag': True},
                "network.static.uri": {'action':'map', 'mapto': "uri", "to_ids": True, 'add_tag': True},
                "file.string.blacklisted":{'action':'map', 'mapto': "text", "to_ids": False, 'add_tag': False},
                "network.static.uri_path":{'action':'map', 'mapto': "text", "to_ids": False, 'add_tag': False},

            }
        }

    }


    def __init__(self, url, apikey, content_type):
        self.content_type = content_type 
        self.misp = pymisp.ExpandedPyMISP(url, apikey, False, False)
        logging.warning("####misp connection created :")
        print("####misp connection created :", type(self.misp)  )

    def findFileObjectBySha256(self,sha256):
        # Search for MISP events containing objects with the specified SHA256
        misp_objs=[]
        try:
            misp_objs = self.misp.search(controller='objects', type_attribute='sha256', attribute=sha256)
            print("------found objects:")
            #pprint(misp_objs)
        except Exception as e:
            print("error finding objects:", e)

        return misp_objs

    def createAttributeWrapper(self,attr_scope,attrib_type, attrib_val):
        print("scope:::::", attr_scope)
        if attr_scope == 'objects':
            attrib=self.createObjectAttribute(attrib_type, attrib_val)

        else:
            attrib=self.createEventAttribute(attrib_type, attrib_val)

        #print("=======++++ in createAttributeWrapper: ")
        #pprint(attrib)
        #de creat toate campurile necesare pentru un attribut !!!!!!!!!!
        return attrib
    
    def createObjectAttribute(self,attrib_type, attrib_val):
        print("[][][][][] Create obj attr:", attrib_type, " val: ", attrib_val)
        
        
        try:
            attribute_def = pymisp.MISPAttribute()
            #attribute_def.from_dict(**{'type':attrib_type, 'value':attrib_val, 'object_relation':attrib_type})
            #print("attrib_def: ", attribute_def)
            attribute = pymisp.MISPObjectAttribute(attribute_def)
            #print("attrib obj:",attribute)
            obj_attrib_type = attrib_type
            if attrib_type == "mime-type":
                obj_attrib_type = "mimetype"
            attribute.from_dict(attrib_type, attrib_val,**{'type':obj_attrib_type})
            print(",.,.,.,. obj attribute created: ", attribute)
        except Exception as e:
            print("Error creating obj attribute: ", e)
        print("[][][][][]  attr returned by createObjectAttribute: ", attribute)
        return attribute
    
    def createEventAttribute(self,attrib_type, attrib_val):
        attribute = pymisp.MISPAttribute()
      
        try:
            attribute.from_dict(**{'type':attrib_type, 'value':attrib_val})
            print("attribute created: ", attribute)
        except Exception as e:
            print("Error creating attribute: ", e)
        return attribute

    def createAttributes(self,attr_scope,al_attr_type, data):
        attributes=[]
        references=[]
        print("####misp in createAttributes :  for:",al_attr_type, " data[al_attr_type:]" , type(data[al_attr_type]))
        for attr_k, attr_v in data[al_attr_type].items():
            print("# # attr type:",type(attr_v), " attr_k:",attr_k)
            if type(attr_v) == list:
                print("self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action']:",self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'])
                pprint(attr_v)
                for item_attr_val in attr_v:
                    if self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'] == 'map':
                        print("####misp in createAttributes list: mapto: ",self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['mapto'])
                        attributes.append(self.createAttributeWrapper(attr_scope,self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['mapto'], item_attr_val))
            elif (type(attr_v) == dict) and (attr_k == 'tags') and (len(attr_v)>0): 
                print("in createAttributes tags: ", attr_k)
                for type_item,value_item in attr_v.items():
                    print("in createAttributes type: ", type_item, " val: ", value_item[0] ,  " type val: ",  type(value_item))
                    if type_item in self.al2misp_mappings[attr_scope][al_attr_type]:
                        print("self.al2misp_mappings[attr_scope][al_attr_type][type_item] : ", self.al2misp_mappings[attr_scope][al_attr_type][type_item])
                        attributes.append(self.createAttributeWrapper(attr_scope,self.al2misp_mappings[attr_scope][al_attr_type][type_item]['mapto'], value_item[0]))
            else:
                print("-=-= else type attr_v:", type(self.al2misp_mappings[attr_scope][al_attr_type]))
                try:    
                    if attr_k in self.al2misp_mappings[attr_scope][al_attr_type]:
                        #pprint(self.al2misp_mappings[attr_scope][al_attr_type])
                        if self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'] == 'map':
                            print("####misp in createAttributes: mapto: ",self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['mapto'])
                            attributes.append(self.createAttributeWrapper(attr_scope,self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['mapto'], attr_v))
                        elif self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'] == 'add_reference':
                            references.append({'referenced_uuid':attr_v, 'relationship_type':self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['mapto']})
                            print("####misp in createAttributes: references: ", references)
                except Exception as e:
                    print("Error createAttribute: ", e)
        #print("####misp in createAttributes :  attributes:",attributes)
        return [attributes,references]

    def createObject(self,al_attr_type, data):
        print("####misp in createObject: al_attr_type: ",al_attr_type)
        misp_object=pymisp.MISPObject(self.al2misp_mappings['objects'][al_attr_type]['mapto'])

    
        [attrs,refs]=self.createAttributes('objects',al_attr_type, data)
        print("***      *   obj created:")
        
        pprint(attrs)
        print("././././././/")
        try:
            #misp_object.add_attributes(attrs)
            for atrib_item in attrs:
                logging.warning("####add attribute to object :")
                print("______________ ret attr: :", atrib_item)
                ret_attr=misp_object.add_attribute(atrib_item.type,atrib_item.value)
                
        except Exception as e:
            print("<>>><>< eeee Error adding attribute to object:", e)
            print("attr type:",atrib_item.type," attr val: ",atrib_item.value)
        #misp_object.attributes=attrs
        #print(misp_object.attributes)
        
        print("====refs:",refs)

        for obj_reference in refs:
            references=self.findFileObjectBySha256(obj_reference['referenced_uuid'])
            #print("references:", references)
            try:
                for reference_item in references:
                    print("   ref uuid: ", reference_item['Object']['uuid'])
                    ret_objref=misp_object.add_reference(reference_item['Object']['uuid'],obj_reference['relationship_type'])
                print("====  ret references:", ret_objref)
            except Exception as e:
                print("No references found", e)
            #print("obj_reference:", obj_reference)
        return misp_object
            
                    

    def createFileObjects(self):
        f_objects=[]
        for ontology_item in self.ontology_result:
            f_objects.append(self.createObject('file',ontology_item))
            logging.warning("####misp createObject: ok")
        self.misp_objects = f_objects
        return f_objects


    def createEventAttributes(self):
        o_data_item={}
        for ontology_item in self.ontology_result:
            print('ontology_item:', type(ontology_item['results']))
            #pprint(ontology_item['results'])
            
            for result_ontology_k,result_ontology_v in ontology_item['results'].items():
                if result_ontology_k in self.ontological_results_types:
                    for result_ontology_v_item in result_ontology_v:
                        print('-=-=-= result_ontology:', type(result_ontology_v_item))
                        
                        #print('result_ontology_v:')
                        #pprint(result_ontology)
                        
                        try:
                            o_data_item['attributes']=result_ontology_v_item
                            o_data_item['attributes']['comment']=result_ontology_k
                            pprint(o_data_item)
                            [attrs,refs]=self.createAttributes('events','attributes', o_data_item)
                        except Exception as e:
                            print("eeee  addEventAttriutes error:", e)
            
            logging.warning("####misp createObject: ok")
            return attrs

    def createTags(self):
        ret_tags=[]
        try:
            tag2add=pymisp.MISPTag()
            tag2add.from_dict(**{'name':'sandbox:AL4'})
            ret_tags.append(tag2add)
        except Exception as e:
            print("err add new tag:",e)
        for result in self.ontology_result:
            if 'tags' in result["results"].keys():
                #print("1111111   tags: ", result["results"]['tags']) 
                for tag_item, tag_val in result["results"]['tags'].items():
                    evttags=[]
                    if tag_item in self.al2misp_mappings['events']['attributes'].keys():
                        #print("self.al2misp_mappings['events']['attributes'][tag_item]['action']:",self.al2misp_mappings['events']['attributes'][tag_item]['action'])
                        if self.al2misp_mappings['events']['attributes'][tag_item]['action'] == "map" and self.al2misp_mappings['events']['attributes'][tag_item]['add_tag'] is True:
                            if type(tag_val) is list:
                                for val_item in tag_val:
                                    evttags.append({'name':self.al2misp_mappings['events']['attributes'][tag_item]['mapto']+':'+urllib.parse.quote(val_item, safe='')})                               
                            else:
                                evttags.append({'name':self.al2misp_mappings['events']['attributes'][tag_item]['mapto']+':'+urllib.parse.quote(tag_val, safe='')})
                            print("....... evttags:", evttags, "tag_item: ", tag_item)
                            for evttag_item in evttags:    
                                try:
                                    print("tag_val :",evttag_item)
                                    tagobj=pymisp.MISPTag()
                                    tagobj.from_dict(**evttag_item)
                                    ret_tags.append(tagobj)
                                except Exception as e:
                                    print("222222  error adding tag: " , evttag_item , " error: ", e)
        return ret_tags

    def addTags2Event(self):
        
        tags=self.createTags()
        #print("***** tags:", tags)
      

        for tag in tags:
            try:
                print("tag to add: ", tag.to_dict()['name'])
                ret_new_tag=self.misp.add_tag(tag) 
                print("9090909090 in addTags2Event ret_tag: ", ret_new_tag)
                ret_add_tag2evt=self.event.add_tag(str(tag.to_dict()['name']))
                print("()()()()() - ret_add_tag2evt:",ret_add_tag2evt)
            except Exception as e:
                print("err add tag ::: " , e)
            #self.event.tags.append(tag.to_dict()['name'])
           
        
        


    def createEvent(self,**submission_attrs):
        
        # date, threat_level, Distribution, analysis, info, extends
        self.event.info = submission_attrs['info']
        self.event.threat_level_id = 2
        self.event.distribution = 0
        self.event.analysis = 1
        
        evt_attrs=self.createEventAttributes()
        self.event.attributes=evt_attrs

        for obj_item in self.misp_objects:
            print(">>>>add object to event....")
            self.event.add_object(obj_item)
        

        #add tags to event
        try:
            #tag1={'color': 'red'}
            #self.event.tags=[tag1]
            self.addTags2Event()
        except Exception as e:
            print("Error add tags: ", e)



        # Add the event to MISP
        try:
            self.resp_event = self.misp.add_event(self.event)
            #print("@@@@@@@@@    self.resp_event: ", self.resp_event['Event'] )
        except Exception as e:
            print("error creating event: ", e)

     