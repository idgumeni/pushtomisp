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
                    'names': {'action':'map', 'params':{'type': 'filename', 'object_relation': 'filename', 'to_ids':False}},
                    'md5': {'action':'map', 'params':{ 'type': 'md5', 'object_relation': 'md5', 'to_ids':False}},
                    "sha1":{'action':'map', 'params':{ 'type': 'sha1', 'object_relation': 'sha1', 'to_ids':False}},
                    "sha256":{'action':'map', 'params':{ 'type': 'sha256', 'object_relation': 'sha256', 'to_ids':False}},
                    "size":{'action':'map', 'params': { 'type': 'size-in-bytes', 'object_relation': 'size-in-bytes', 'to_ids':False}},
                    "type":{'action':'map', 'params': { 'type': 'mime-type', 'object_relation': 'mimetype', 'to_ids':False}},
                    "parent":{'action':'add_reference', 'params':{ 'type': 'child-of', 'relationship_type': 'child-of', 'to_ids':False}},
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
            logging.warning("####misp connection created :")
            #print("####misp connection created :", type(self.misp)  )
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
        print("   3 -***-----found defined objects:")
        pprint(self.misp_objects)
        try:
            #misp_objs = self.misp.search(controller='objects', type_attribute='sha256', attribute=sha256)
            #search in current MISPObjects from self.misp_objects
            for obj_item in self.misp_objects:
              for obj_attr in obj_item.to_dict().get('Attribute'):
                obj_dict = obj_attr.to_dict()
                print("   3 ()()()()()     findFileObject  obj_dict :", obj_dict['value'] ,' obj_dict[object_relation]:',obj_dict['object_relation'], ' for sha256:',sha256)

                if (obj_dict['object_relation'] == 'sha256') and  ( obj_dict['value'] == sha256 ):
                    misp_objs.append(obj_item['uuid'])
                    break

        except Exception as e:
            print("error finding objects:", e)

        return misp_objs


    
    # def createEventAttribute(self,attrib_val, **attrib_dict):
    #     attribute = pymisp.MISPAttribute()
    #     try:
    #         attribute.from_dict(value=attrib_dict['value'],**attrib_dict)
    #         print("createEventAttribute  attribute created: ", attribute)
    #     except Exception as e:
    #         print("Error createEventAttribute  Error creating attribute: ", e)
    #     return attribute

    def recursiveIteration(self,mixeddata):
        print(">>> data type:%s" % (type(mixeddata)))
        if isinstance(mixeddata,list):
            for dataitem in mixeddata:
                self.recursiveIteration(dataitem)
        elif isinstance(mixeddata,dict):
            try:
                for k,v in mixeddata.items():
                    print("k: %s v type:%s" % (k,type(v)))
                    if isinstance(v,dict) or isinstance(v,list):  
                        print("->call recursiveIteration")
                        self.recursiveIteration(v)
                    else:
                        print("..... ri: %s: %s  type:%s" %(k,v, type(v)))
                        
                        return k,v    
            except Exception as e:
                print("Error recursiveIteration:", e)


    def createAttributesDict2(self,attr_scope,al_attr_type, data):
        #data:'file': {...}
        attributes=[]
        references=[]
        try:
            for k,v in self.recursiveIteration(data):
                if k in self.al2misp_mappings[attr_scope][al_attr_type]:
                    if self.al2misp_mappings[attr_scope][al_attr_type][k]['action'] == 'map':
                        print("#### createObjectAttributes list: to: ",self.al2misp_mappings[attr_scope][al_attr_type][k]['to'])
                        print("#### createObjectAttributes: atributes: %s: %s" % (k,v))
                        attributes.append(dict({'value':v, **self.al2misp_mappings[attr_scope][al_attr_type][k]['params']}))
                    elif self.al2misp_mappings[attr_scope][al_attr_type][k]['action'] == 'add_reference':
                        references.append({'referenced_uuid':v}, self.al2misp_mappings[attr_scope][al_attr_type][k]['params'])
                        print("#### createObjectAttributes: references: %s: %s" % (k,v))
        except Exception as e:
            print("Error createAttributesDict2:",e)
        return [attributes,references]

    def createAttributesDict(self,attr_scope,al_attr_type, data):
        #data:'file': {...}
        attributes=[]
        references=[]
        
        #attr_scope='objects'
        print("####>>>>> createObjectAttributes :  for:",al_attr_type, " data[al_attr_type]:" )
        #pprint(data[al_attr_type])
        for attr_k, attr_v in data[al_attr_type].items():
            #print("# # attr type:",type(attr_v), " attr_k:",attr_k)
            if type(attr_v) == list:
                print(" createObjectAttributes if self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action']:",self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'])
                try:
                    #pprint(attr_v)
                    for item_attr_val in attr_v:
                        if self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'] == 'map':
                            print("#### createObjectAttributes list: to: ",self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['to'])
                            attributes.append(dict({'value':item_attr_val, **self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['params']}))
                        elif self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'] == 'add_reference':
                            references.append({'referenced_uuid':attr_v}, self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['params'])
                            #print("#### createObjectAttributes: references: ", references)
                except Exception as e:
                    print("Error creating attributeDict item (list):", e)
            elif (type(attr_v) == dict) and (attr_k == 'tags') and (len(attr_v)>0): 
                #print("?????????? createObjectAttributes elif tags: ", attr_k)
                try:
                    for type_item,value_item in attr_v.items():
                        print("in createObjectAttributes type: ", type_item, " val: ", value_item[0] ,  " type val: ",  type(value_item))
                        if type_item in self.al2misp_mappings[attr_scope][al_attr_type]:
                            #print("createObjectAttributes self.al2misp_mappings[attr_scope][al_attr_type][type_item] : ", self.al2misp_mappings[attr_scope][al_attr_type][type_item])
                            attributes.append(dict({'value': value_item[0], **self.al2misp_mappings[attr_scope][al_attr_type][type_item]['params']}))
                except Exception as e:
                    print("Error creating attributeDict item (tags)")
            else:
                #print("-=-=createObjectAttributes else type attr_v:", type(self.al2misp_mappings[attr_scope][al_attr_type]))
                try:    
                    if attr_k in self.al2misp_mappings[attr_scope][al_attr_type]:
                        pprint(self.al2misp_mappings[attr_scope][al_attr_type])
                        if self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'] == 'map':
                            #print("####createObjectAttributes: to: ",self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['to'])
                            attributes.append(dict({'value': attr_v, **self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['params']}))
                        elif self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'] == 'add_reference':
                            references.append(dict({'referenced_uuid':attr_v}, **self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['params']))
                            print("#### createObjectAttributes: references: key:", attr_k, " val:" , attr_v)
                except Exception as e:
                    print("rror creating attributeDict item (else):: ", e)
        #print("####misp in createAttributes :  attributes:",attributes)
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


    # def createAttributes(self,attrs_obj_dict):
    #     attributes=[]
    #     for attr_obj_dict in attrs_obj_dict:
    #         attributes.append(self.createAttribute(attr_obj_dict))
    #     return attributes

    

    def createObject(self, attrs_object_dict):
        #, refs_objects_list
        try:
            misp_object=pymisp.MISPObject('file')
        except Exception as e:
            print("error creating misp obj:",e)

        #attrs_list=self.createAttributes(attrs_object_dict)    
        try:
            for atrib_item in attrs_object_dict:
                #logging.warning("####add attribute to object :")
                #print("______________ ret attr: :", atrib_item)
                ret_attr=misp_object.add_attribute( **atrib_item)
                #print('---createObject  ret_attr:', ret_attr)
        except Exception as e:
            print("<>>><>< eeee Error adding attribute to object:", e)
        
        # try:
        #     for reference_item in refs_objects_list:
        #         print("   ref uuid: ", reference_item)
        #         ret_objref=misp_object.add_reference(reference_item['uuid'], reference_item['relationship_type'])
        #         print("==== createObject ret references:", ret_objref)
        # except Exception as e:
        #     print("No references found", e)
            
        return misp_object
            
            

    # def createObjectDict(self,al_attr_type, data):
    #     print("  2 ####misp in createObject: al_attr_type: ",al_attr_type) 
    #     # try:
    #     #     misp_object=pymisp.MISPObject(self.al2misp_mappings['objects'][al_attr_type]['to'])
    #     # except Exception as e:
    #     #     print("error creating misp obj:",e)

    #     ret_obj_refs_list=[]

    #     [attrs_dict,obj_refs]=self.createAttributesDict('objects',al_attr_type, data)
 
    #     for obj_reference in obj_refs:
    #         references=self.findFileObjectBySha256(obj_reference['referenced_uuid'])
    #         #print("references:", references)
    #         try:
    #             for reference_item in references:
    #                 ret_obj_refs_list.append(dict({'referenced_uuid':reference_item, 'relationship_type':obj_reference['relationship_type']}))
    #         except Exception as e:
    #             print("Error  createObjectDict No references found", e)

    #     return [ attrs_dict, ret_obj_refs_list]            



    def createFileObjects(self):
        f_objects=[]
        f_objects_data={}
        f_objects_data['attrs_object_dicts']=[]
        f_objects_data['refs_objects_list']=[]
        cnt=0
        for ontology_item in self.ontology_result:
            try:
                #[attrs_object_dict, refs_objects_list]=self.createObjectDict('file',ontology_item)
                [attrs_object_dict,refs_objects_list]=self.createAttributesDict2('objects','file', ontology_item)
                #check for duplicates objects in ontology
                if attrs_object_dict not in f_objects_data['attrs_object_dicts']:
                    f_objects_data['attrs_object_dicts'].append(attrs_object_dict)
                    f_objects_data['refs_objects_list'].append(refs_objects_list)
                    print('  2 cnt:',cnt)
                    cnt=cnt+1
                    
                    obj_item=self.createObject(attrs_object_dict) #, f_objects_data['refs_objects_list'][i]
                    #print("  2 = ===== obj item created:", obj_item.to_dict())
                    f_objects.append(obj_item)
                    self.misp_objects = f_objects
                    #add references
                    for obj_reference in refs_objects_list:
                        references=self.findFileObjectBySha256(obj_reference['referenced_uuid'])
                        print("   3 ----- references:", references)
                        try:
                            for reference_item in references:
                                #ret_obj_refs_list.append(dict({'referenced_uuid':reference_item, 'relationship_type':obj_reference['relationship_type']}))
                                print('add references: uuid:', reference_item , " relationship: ",  obj_reference['relationship_type'])
                                ref_ret=obj_item.add_reference(reference_item, obj_reference['relationship_type'])
                                print(' ret_add ref:', ref_ret)
                        except Exception as e:
                            print("Error  createObjectDict No references found", e)

            except Exception as e:
                print('^^^^^err creating objects dict:',e)

        #print('type (f_objects[objects_names]):', type(f_objects_data['attrs_object_dicts']))
        print("  identified " + str(cnt) + " objects")
        # for i,attrs_object in enumerate(f_objects_data['attrs_object_dicts']):
        #     obj_item=self.createObject(attrs_object) #, f_objects_data['refs_objects_list'][i]
        #     #print("= ===== obj item:", obj_item.to_dict())
        #     f_objects.append(obj_item)
        #     #add references
        #     for obj_reference in f_objects_data['refs_objects_list'][i]:
        #         references=self.findFileObjectBySha256(obj_reference['referenced_uuid'])
        #         #print("references:", references)
        #         try:
        #             for reference_item in references:
        #                 #ret_obj_refs_list.append(dict({'referenced_uuid':reference_item, 'relationship_type':obj_reference['relationship_type']}))
        #                 obj_item.add_reference(reference_item, obj_reference['relationship_type'])
        #         except Exception as e:
        #             print("Error  createObjectDict No references found", e)

        #logging.warning("####misp createObject: ok" + obj_item.to_dict())    
        

        return f_objects


    def createEventAttributes(self,evt_attrs_dict):
        evt_attr_objects=[]
        #print('event - evt_attrs_dict:', evt_attrs_dict)
        for attr_item in evt_attrs_dict:
            #print('event - - attr_item:', attr_item)
            try:
                evt_attr_objects.append(self.createAttribute(attr_item))
            except Exception as e:
                print('Error createAttribute error creating attribute: ', e)
        
        return evt_attr_objects
        

    def createEventAttributesDict(self):
        o_data_item={}
        event_attrs=[]
        print("++++ count self.ontology_result : ", len(self.ontology_result))
        cnt_res=0
        for ontology_item in self.ontology_result:
            print('+ ontology_item:', type(ontology_item['results']))
            print('+ ontology_item result cnt_res:', cnt_res , " len: ", len(ontology_item['results']))
            cnt_res=cnt_res+1
            #pprint(ontology_item['results'])
            try:
                result_items=ontology_item['results'].items()
            except Exception as e:
                print("Error iterating through result items:", e)
                break;
        
            for result_ontology_k,result_ontology_v in result_items:
                print(' \  \  \  ontology_item result_ontology_k:',result_ontology_k)
                try:
                    type_res=type(result_ontology_v)
                    print("type(result_ontology_v) : ", type(result_ontology_v))
                except Exception as e:
                    print("+++ error type res:", e)
                if (result_ontology_k in self.ontological_results_types) and (type(result_ontology_v) is list) and (len(result_ontology_v)>0) :
                    self.evt_tags.append(dict({'name':'detection:'+result_ontology_k}))
                    #print('\\\\\\\\\  ontology_item result_ontology_k:',result_ontology_k)
                    #print('ontology_item result_ontology_v:',result_ontology_v)
                    for result_ontology_v_item in result_ontology_v:
                        


                        print('-=-=-= result_ontology:', type(result_ontology_v_item))
                        
                        print('___result_ontology_v:')
                        
                        o_data_item['attributes']=result_ontology_v_item
                        
                        o_data_item['attributes']['comment']=result_ontology_k
                        #pprint(o_data_item)
                        try:
                            
                            print("o_data_item:")
                            #pprint(o_data_item)
                            [attrs,refs]=self.createAttributesDict2('events','attributes', o_data_item)
                            event_attrs = event_attrs + attrs
                        except Exception as e:
                            print("eeee  addEventAttriutes error:", e)
         
        logging.warning("####misp createObject: ok")
        return event_attrs
        

    def createTags(self):
        ret_tags=[]
        for tag_item in self.evt_tags:
            print("tag_item:", tag_item)
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
        self.evt_tags.append( dict({'name':self.tool_name})) # extract from config file in __init__
        tags=self.createTags()
        #print("***** tags:", tags)
      

        for tag in tags:
            try:
                #print("tag to add: ", tag.to_dict()['name'])
                ret_new_tag=self.misp.add_tag(tag) 
                #print("9090909090 in addTags2Event ret_tag: ", ret_new_tag)
                ret_add_tag2evt=self.event.add_tag(str(tag.to_dict()['name']))
                #print("()()()()() - ret_add_tag2evt:",ret_add_tag2evt)
            except Exception as e:
                print("err addTags2Event  add tag ::: " , e)
            #self.event.tags.append(tag.to_dict()['name'])
           
        
        


    def createEvent(self,**submission_attrs):
        
        # date, threat_level, Distribution, analysis, info, extends
        self.event.info = submission_attrs['info']
        self.event.threat_level_id = self.threat_level_id
        self.event.distribution = self.distribution
        self.event.analysis = self.analysis
        #{'classification':classification ,'date':analysis_date,'max_score':score,'info':description }
        self.evt_tags.append(dict({'name':'classification:' + submission_attrs['classification']}))

        evt_attrs_dict=self.createEventAttributesDict()
        print("_____ evt attrs:", evt_attrs_dict)
        evt_attrs=self.createEventAttributes(evt_attrs_dict)
        #self.event.attributes=evt_attrs
        for attr in evt_attrs:
            self.event.add_attribute(**attr)

        print("<><> createEvent: ", self.event.attributes)
        #self.event.objects=self.misp_objects
        try:
            for obj_item in self.misp_objects:
                print(">>>>add object to event....",obj_item.to_dict() )
                ret_add_obj=self.event.add_object(obj_item)
                print(">>>>add object to event....ret:",ret_add_obj )
        except Exception as e:
            print('error ading object to event : ',e)
        
        print("<><> createEvent dupa add obj attribs: ", self.event.attributes)
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

        print("<><> 3 createEvent dupa add event attribs: ", self.event.attributes)

     
        #self.event.publish()
        #print(self.event.published)


