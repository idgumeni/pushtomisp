import pymisp
import logging
from pprint import pprint

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
    ontological_results=['antivirus','malwareconfig','netflow','process','sandbox','signature','heuristics']
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
        'event':{
            'attributes':{
                "network.static.domain":{'action':'map', 'mapto': 'domain', "to_ids": True, 'tag':True},
                "network.static.uri": {'action':'map', 'mapto': "uri", "to_ids": True, 'tag':True},
                "file.string.blacklisted":{'action':'map', 'mapto': "text", "to_ids": False, 'tag':False},
                "network.static.uri_path":{'action':'map', 'mapto': "text", "to_ids": False, 'tag':False},

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
        type_key='type'
        try:
            attribute.from_dict(**{type_key:attrib_type, 'value':attrib_val})
            print("attribute created: ", attribute)
        except Exception as e:
            print("Error creating attribute: ", e)
        return attribute

    def createAttributes(self,attr_scope,al_attr_type, data):
        attributes=[]
        references=[]
        print("####misp in createAttributes :  for:",al_attr_type)
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
            for reference_item in references:
                print("   ref uuid: ", reference_item['Object']['uuid'])
                ret_objref=misp_object.add_reference(reference_item['Object']['uuid'],obj_reference['relationship_type'])
            print("====  ret references:", ret_objref)
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
                if result_ontology_k in self.ontological_results:
                    for result_ontology_v_item in result_ontology_v:
                        print('-=-=-= result_ontology:', type(result_ontology_v_item))
                        
                        #print('result_ontology_v:')
                        #pprint(result_ontology)
                        
                        try:
                            o_data_item['attributes']=result_ontology_v_item
                            o_data_item['attributes']['comment']=result_ontology_k
                            pprint(o_data_item)
                            [attrs,refs]=self.createAttributes('event','attributes', o_data_item)
                        except Exception as e:
                            print("eeee  addEventAttriutes error:", e)
            
            logging.warning("####misp createObject: ok")
            return attrs


    def createEvent(self,**submission_attrs):
        event = pymisp.MISPEvent()
        # date, threat_level, Distribution, analysis, info, extends
        event.info = submission_attrs['info']
        event.threat_level_id = 2
        event.distribution = 0
        event.analysis = 1
        
        evt_attrs=self.createEventAttributes()
        event.attributes=evt_attrs
        #pprint(evt_attrs)
        # for evt_attr in evt_attrs:
        #     pprint(evt_attr)
        #     try:
        #         event.add_attribute(evt_attr)
        #     except Exception as e:
        #         print("err adding attribute to event: ", e)
        # # event.add_object(misp_object)
        for obj_item in self.misp_objects:
            print(">>>>add object to event....")
            event.add_object(obj_item)
        
        #add tags to event
        

        # Add the event to MISP
        try:
            response = self.misp.add_event(event)
        except Exception as e:
            print("error creating event: ", e)



#    def createEvent(self,attributes):

#     def add_attribute_to_event(value, category, type, comment, to_ids, tags):
#         misp_attribute = MISPAttribute()
#         misp_attribute.value = str(value)
#         misp_attribute.category = str(category)
#         misp_attribute.type = str(type)
#         misp_attribute.comment = str(comment)
#         misp_attribute.to_ids = str(ids)
#         for x in tags:
#                 misp_attribute.add_tag(x)
#         r = pymisp.add_attribute(self.event, misp_attribute)


#     def add_event(jsondata):
#         self.event = self.misp.add_event(jsondata)

#    # Create attributes
#     attributes = []
#     for f in files:
#         a = MISPAttribute()
#         a.type = arg_type
#         a.value = f.name
#         a.data = f
#         a.comment = args.comment
#         a.distribution = args.distrib
#         if args.expand and arg_type == 'malware-sample':
#             a.expand = 'binary'
#         attributes.append(a)


#         m = MISPEvent()
#         m.info = args.info
#         m.distribution = args.distrib
#         m.attributes = attributes
#         if args.expand and arg_type == 'malware-sample':
#             m.run_expansions()
#         misp.add_event(m)




#     def add_attribute_to_event(value, category, type, comment, to_ids, tags):
#         misp_attribute = MISPAttribute()
#         misp_attribute.value = str(value)
#         misp_attribute.category = str(category)
#         misp_attribute.type = str(type)
#         misp_attribute.comment = str(comment)
#         misp_attribute.to_ids = str(ids)
#         for x in tags:
#                 misp_attribute.add_tag(x)
#         r = pymisp.add_attribute(self.event, misp_attribute)


#     def upload_sample();
         


#to do  de convertit AL ontology (file, service, results, classification, max_score to misp attribute.)