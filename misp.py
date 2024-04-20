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
    evt_tags=[]
    event = pymisp.MISPEvent()
    resp_event = {}
    ontological_results_types=['antivirus','malwareconfig','netflow','process','sandbox','signature','heuristics']
    object_name_fields = ['filename']
# self._file_mapping = {'entropy': {'type': 'float', 'object_relation': 'entropy'},
#                   'md5': {'type': 'md5', 'object_relation': 'md5'},
#                   'mime': {'type': 'mime-type', 'object_relation': 'mimetype'},
#                   'sha1': {'type': 'sha1', 'object_relation': 'sha1'},
#                   'sha256': {'type': 'sha256', 'object_relation': 'sha256'},
#                   'size': {'type': 'size-in-bytes', 'object_relation': 'size-in-bytes'},
#                   'ssdeep': {'type': 'ssdeep', 'object_relation': 'ssdeep'}}
    al2misp_mappings={ #AL:MISP
        'objects':{
            'file':{'to':'file',
                    'names': {'action':'map', 'to': 'filename', 'obj_type': 'filename'},
                    'md5': {'action':'map', 'to': 'md5', 'obj_type': 'md5'},
                    "sha1":{'action':'map', 'to': 'sha1', 'obj_type': 'sha1'},
                    "sha256":{'action':'map', 'to': 'sha256', 'obj_type': 'sha256'},
                    "size":{'action':'map', 'to': 'size-in-bytes', 'obj_type': 'size-in-bytes'},
                    "parent":{'action':'add_reference', 'to': 'child-of', 'obj_type': 'child-of'},
            },

        },
        'events':{
            'attributes':{
                "network.static.domain":{'action':'map', 'to': 'domain', "to_ids": True, 'ref':'communicates-with'},
                "network.static.uri": {'action':'map', 'to': "uri", "to_ids": True, 'ref':'communicates-with'},
                "file.string.blacklisted":{'action':'map', 'to': "text", "to_ids": False, 'ref':'capability'},
                "network.static.uri_path":{'action':'map', 'to': "text", "to_ids": False, 'ref':'communicates-with'},

            }
        }

    }


    def __init__(self, url, apikey, content_type):
        self.content_type = content_type 
        self.misp = pymisp.ExpandedPyMISP(url, apikey, False, False)
        logging.warning("####misp connection created :")
        #print("####misp connection created :", type(self.misp)  )

    def findFileObjectBySha256(self,sha256):
        # Search for MISP events containing objects with the specified SHA256
        misp_objs=[]
        try:
            #misp_objs = self.misp.search(controller='objects', type_attribute='sha256', attribute=sha256)
            #search in current MISPObjects from self.misp_objects
            #for obj_item in self.misp_objects:
            #   obj_dict=obj_item.to_dict()
            #   print("obj_item:")
            #   print(obj_dict)
            #   if obj_dict['sha256'] == sha256:
            #       misp_objs.append(obj_dict['uuid'])
            print("------found objects:")
            #pprint(misp_objs)
        except Exception as e:
            print("error finding objects:", e)

        return misp_objs


    
    def createAttributeWrapperDict(self,attr_scope, attrib_val, **attrib_dict):
        print("createAttributeWrapper - scope:::::", attr_scope)
        if attr_scope == 'objects':
            attrib=self.createObjectAttributeDict( attrib_val, **attrib_dict)

        else:
            attrib=self.createEventAttributeDict(  attrib_val, **attrib_dict)

        #print("=======++++ in createAttributeWrapper: ")
        #pprint(attrib)
        #de creat toate campurile necesare pentru un attribut !!!!!!!!!!
        return attrib
    
    
    def createObjectAttributeDict(self, attrib_val, **attrib_dict):
        attribute_dict = dict({'object_relation':attrib_dict['to'], 'value': attrib_val, 'type':attrib_dict['obj_type']})
        return attribute_dict
    
    
    def createEventAttribute(self,attrib_val, **attrib_dict):
        attribute = pymisp.MISPAttribute()
        try:
            attribute.from_dict(**{'type':attrib_dict['to'], 'value':attrib_val, 'to_ids':attrib_dict['to_ids']})
            print("attribute created: ", attribute)
        except Exception as e:
            print("Error creating attribute: ", e)
        return attribute


    def createEventAttributeDict(self,attrib_val, **attrib_dict):
        attribute_dict = dict({'type':attrib_dict['to'], 'value':attrib_val, 'to_ids':attrib_dict['to_ids']})
        return attribute_dict



    def createAttributesDict(self,attr_scope,al_attr_type, data):
        #data:'file': {...}
        attributes=[]
        references=[]
        
        #attr_scope='objects'
        print("####>>>>> createObjectAttributes :  for:",al_attr_type, " data[al_attr_type]:" )
        #pprint(data[al_attr_type])
        for attr_k, attr_v in data[al_attr_type].items():
            print("# # attr type:",type(attr_v), " attr_k:",attr_k)
            if type(attr_v) == list:
                print(" createObjectAttributes if self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action']:",self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'])
                #pprint(attr_v)
                for item_attr_val in attr_v:
                    if self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'] == 'map':
                        #print("#### createObjectAttributes list: to: ",self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['to'])
                        attributes.append(self.createAttributeWrapperDict(attr_scope, item_attr_val, **self.al2misp_mappings[attr_scope][al_attr_type][attr_k]))
                    elif self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'] == 'add_reference':
                        references.append({'referenced_uuid':attr_v, 'relationship_type':self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['to']})
                        #print("#### createObjectAttributes: references: ", references)
            elif (type(attr_v) == dict) and (attr_k == 'tags') and (len(attr_v)>0): 
                #print("?????????? createObjectAttributes elif tags: ", attr_k)
                for type_item,value_item in attr_v.items():
                    #print("in createObjectAttributes type: ", type_item, " val: ", value_item[0] ,  " type val: ",  type(value_item))
                    if type_item in self.al2misp_mappings[attr_scope][al_attr_type]:
                        #print("createObjectAttributes self.al2misp_mappings[attr_scope][al_attr_type][type_item] : ", self.al2misp_mappings[attr_scope][al_attr_type][type_item])
                        attributes.append(self.createAttributeWrapperDict(attr_scope, value_item[0], **self.al2misp_mappings[attr_scope][al_attr_type][type_item]))
            else:
                #print("-=-=createObjectAttributes else type attr_v:", type(self.al2misp_mappings[attr_scope][al_attr_type]))
                try:    
                    if attr_k in self.al2misp_mappings[attr_scope][al_attr_type]:
                        #pprint(self.al2misp_mappings[attr_scope][al_attr_type])
                        if self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'] == 'map':
                            #print("####createObjectAttributes: to: ",self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['to'])
                            attributes.append(self.createAttributeWrapperDict(attr_scope, attr_v, **self.al2misp_mappings[attr_scope][al_attr_type][attr_k]))
                        elif self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'] == 'add_reference':
                            references.append({'referenced_uuid':attr_v, 'relationship_type':self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['to']})
                            #print("#### createObjectAttributes: references: ", references)
                except Exception as e:
                    print("Error createAttribute: ", e)
        #print("####misp in createAttributes :  attributes:",attributes)
        return [attributes,references]
    
    def createAttribute(self,attr_dict):
        attribute = pymisp.MISPAttribute()
        try:
            attribute.from_dict(**attr_dict)
            print("attribute created: ", attribute)
        except Exception as e:
            print("Error creating attribute: ", e)
        return attribute


    def createAttributes(self,attrs_obj_dict):
        attributes=[]
        for attr_obj_dict in attrs_obj_dict:
            attributes.append(self.createAttribute(attr_obj_dict))
        return attributes

    

    def createObjectDict(self,al_attr_type, data):
        print("####misp in createObject: al_attr_type: ",al_attr_type) 
        try:
            misp_object=pymisp.MISPObject(self.al2misp_mappings['objects'][al_attr_type]['to'])
        except Exception as e:
            print("error creating misp obj:",e)

        ret_obj_refs_list=[]
        misp_object_name = ''
        [attrs_dict,obj_refs]=self.createAttributesDict('objects',al_attr_type, data)
        print('**** attrs  dict:', attrs_dict)
        print('**** obj_refs  dict:', obj_refs)
        for attr_rel in attrs_dict:
            if attr_rel['object_relation'] in self.object_name_fields:
                print('@@@@@ attr_rel: ', attr_rel['value'])
                misp_object_name=attr_rel['value']
                print('@@@@@ misp_object_name: ', misp_object_name)
 
        for obj_reference in obj_refs:
            references=self.findFileObjectBySha256(obj_reference['referenced_uuid'])
            #print("references:", references)
            try:
                for reference_item in references:
                    ret_obj_refs_list.append(dict({'referenced_uuid':reference_item, 'relationship_type':obj_reference['relationship_type']}))
            except Exception as e:
                print("No references found", e)

        return [ misp_object_name, attrs_dict, ret_obj_refs_list]            

    def createObject(self,object_name, attrs_object_dict, refs_objects_list):
        try:
            misp_object=pymisp.MISPObject(object_name)
        except Exception as e:
            print("error creating misp obj:",e)

        attrs_list=self.createAttributes(attrs_object_dict)    
        try:
            for atrib_item in attrs_list:
                logging.warning("####add attribute to object :")
                print("______________ ret attr: :", atrib_item)
                ret_attr=misp_object.add_attribute(atrib_item)
                print('ret_attr:', ret_attr)
        except Exception as e:
            print("<>>><>< eeee Error adding attribute to object:", e)
           
        
        try:
            for reference_item in refs_objects_list:
                print("   ref uuid: ", reference_item)
                ret_objref=misp_object.add_reference(reference_item['uuid'], reference_item['relationship_type'])
                print("==== createObject ret references:", ret_objref)
        except Exception as e:
            print("No references found", e)
            
        return misp_object
            


    def createFileObjects(self):
        f_objects=[]
        f_objects_data={}
        f_objects_data['attrs_object_dicts']=[]
        f_objects_data['objects_names']=[]
        f_objects_data['refs_objects_list']=[]
        cnt=0
        for ontology_item in self.ontology_result:
            #pprint(ontology_item)
            #createFileObjectDict
            try:
                [object_name, attrs_object_dict, refs_objects_list]=self.createObjectDict('file',ontology_item)
                if attrs_object_dict not in f_objects_data['attrs_object_dicts']:
                    f_objects_data['attrs_object_dicts'].append(attrs_object_dict)
                    f_objects_data['objects_names'].append(object_name)
                    f_objects_data['refs_objects_list'].append(refs_objects_list)
                    cnt=cnt+1
                else:
                    print("!!!!!!! object already exists !!! " ,object_name)
                #obj_item = self.createObject('file',ontology_item)
                #f_objects.append(obj_item)
                print('-=-=-=-=-=>>')
                pprint(f_objects_data)
                print('-=-=-=-=-=<< - len:', len(f_objects_data))
               
            except Exception as e:
                print('^^^^^err creating objects dict:',e)

         #TODO create objects from dicts!!!!!!!!!
        print('type (f_objects[objects_names]):', type(f_objects_data['attrs_object_dicts']))
        for i,obj_name in enumerate(f_objects_data['objects_names']):
            print('&&&&&&  obj_name type:', type(obj_name))
            if obj_name == '':
                obj_name='-'
            obj_item=self.createObject(obj_name, f_objects_data['attrs_object_dicts'][i], f_objects_data['refs_objects_list'][i])
            print("= ===== obj item:", obj_item)
            f_objects.append(obj_item)
        #logging.warning("####misp createObject: ok" + obj_item.to_dict())    
        self.misp_objects = f_objects
        return f_objects


    def createEventAttributes(self,evt_attrs_dict):
        evt_attr_objects=[]
        print('event - evt_attrs_dict:', evt_attrs_dict)
        for attr_item in evt_attrs_dict:
            print('event - - attr_item:', attr_item)
            evt_attr_objects.append(self.createAttribute(attr_item))
        
        return evt_attr_objects
        

    def createEventAttributesDict(self):
        o_data_item={}
        event_attrs=[]
        for ontology_item in self.ontology_result:
            print('ontology_item:', type(ontology_item['results']))
            print('ontology_item result:')
            pprint(ontology_item['results'])
            
            for result_ontology_k,result_ontology_v in ontology_item['results'].items():
                
                if result_ontology_k in self.ontological_results_types:
                    self.evt_tags.append(dict({'name':'detection:'+result_ontology_k}))
                    for result_ontology_v_item in result_ontology_v:
                        print('-=-=-= result_ontology:', type(result_ontology_v_item))
                        
                        #print('result_ontology_v:')
                        #pprint(result_ontology)
                        
                        try:
                            o_data_item['attributes']=result_ontology_v_item
                            o_data_item['attributes']['comment']=result_ontology_k
                            pprint(o_data_item)
                            [attrs,refs]=self.createAttributesDict('events','attributes', o_data_item)
                            event_attrs = event_attrs + attrs
                        except Exception as e:
                            print("eeee  addEventAttriutes error:", e)
            
            logging.warning("####misp createObject: ok")
            return event_attrs
        

    def createTags(self):
        ret_tags=[]
        for tag_item in self.evt_tags:
            try:
                tagobj=pymisp.MISPTag()
                tagobj.from_dict(**tag_item)
                ret_tags.append(tagobj)
            except Exception as e:
                print("222222 createTags  error adding tag: " , tag_item , " error: ", e)
        #add tags from AL tags dictionary - not recommended
        # for result in self.ontology_result:
        #     if 'tags' in result["results"].keys():
        #         #print("1111111   tags: ", result["results"]['tags']) 
        #         for tag_item, tag_val in result["results"]['tags'].items():
        #             evttags=[]
        #             if tag_item in self.al2misp_mappings['events']['attributes'].keys():
        #                 #print("self.al2misp_mappings['events']['attributes'][tag_item]['action']:",self.al2misp_mappings['events']['attributes'][tag_item]['action'])
        #                 if self.al2misp_mappings['events']['attributes'][tag_item]['action'] == "map" and self.al2misp_mappings['events']['attributes'][tag_item]['add_tag'] is True:
        #                     if type(tag_val) is list:
        #                         for val_item in tag_val:
        #                             evttags.append({'name':self.al2misp_mappings['events']['attributes'][tag_item]['to']+':'+urllib.parse.quote(val_item, safe='')})                               
        #                     else:
        #                         evttags.append({'name':self.al2misp_mappings['events']['attributes'][tag_item]['to']+':'+urllib.parse.quote(tag_val, safe='')})
        #                     print("....... evttags:", evttags, "tag_item: ", tag_item)
        #                     for evttag_item in evttags:    
        #                         try:
        #                             print("tag_val :",evttag_item)
        #                             tagobj=pymisp.MISPTag()
        #                             tagobj.from_dict(**evttag_item)
        #                             ret_tags.append(tagobj)
        #                         except Exception as e:
        #                             print("222222  error adding tag: " , evttag_item , " error: ", e)
        return ret_tags

    def addTags2Event(self):
        self.evt_tags.append( dict({'name':'sandbox:AL4'})) # extract from config file in __init__
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
        
        evt_attrs_dict=self.createEventAttributesDict()
        evt_attrs=self.createEventAttributes(evt_attrs_dict)
        self.event.attributes=evt_attrs
        self.event.objects=self.misp_objects
        # try:
        #     for obj_item in self.misp_objects:
        #         print(">>>>add object to event....",obj_item )
        #         self.event.add_object(obj_item)
        # except Exception as e:
        #     print('error ading object to event : ',e)
        

        #add tags to event
        try:
            #tag1={'color': 'red'}
            #self.event.tags=[tag1]
            self.addTags2Event()
        except Exception as e:
            print("Error add tags: ", e)

        #add references to evts:


        # Add the event to MISP
        try:
            self.resp_event = self.misp.add_event(self.event)
            #print("@@@@@@@@@    self.resp_event: ", self.resp_event['Event'] )
        except Exception as e:
            print("error creating event: ", e)

     