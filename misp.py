import pymisp
import logging


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
    ontology_result=[]
    misp_objects = []
    evt_attributes = []
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
        'attributes':{
            "network.static.domain":"domain",
            "network.static.uri": "uri",
            "file.string.blacklisted":"text",

        }

    }


    def __init__(self, url, apikey, content_type):
        self.content_type = content_type 
        self.misp = pymisp.PyMISP(url, apikey, False, False)
        logging.warning("####misp connection created :")
        print("####misp connection created :", type(self.misp)  )

    def findFileObjectBySha256(self,sha256):
        # Search for MISP events containing objects with the specified SHA256
        misp_objects = self.misp.search(controller='objects', type_attribute='sha256', attribute=sha256)
        return misp_objects

    def createAttribute(self,attrib_type, attrib_val):
        attribute = pymisp.MISPAttribute()
        print("creating attribute: ", attrib_type)
        try:
            attribute.from_dict(**{'type':attrib_type, 'value':attrib_val, 'to_ids': True})
            print("attribute created: ", attribute)
        except Exception as e:
            print("Error creating attribute: ", e)
        logging.warning("####misp attribute created attribute: ")
        #de creat toate campurile necesare pentru un attribut !!!!!!!!!!
        return attribute

    def createAttributes(self,attr_scope,al_attr_type, data):
        
        attributes=[]
        references=[]
        print("####misp in createAttributes :  for:",data[al_attr_type])
        for attr_k, attr_v in data[al_attr_type].items():
            print("####misp in createAttributes :  attr_k:",attr_k)
            if type(attr_v) == list:
                for item_attr_val in attr_v.items():
                    if self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'] == 'map':
                        print("####misp in createAttributes list: mapto: ",self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['mapto'])
                        attributes.append(self.createAttribute(self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['mapto'], item_attr_val))
            else:
                if self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'] == 'map':
                    print("####misp in createAttributes: mapto: ",self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['mapto'])
                    attributes.append(self.createAttribute(self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['mapto'], attr_v))
                elif self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'] == 'add_reference':
                    references.append({'referenced_uuid':attr_v, 'relationship_type':self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['mapto']})
        return [attributes,references]

    def createObject(self,al_attr_type, data):
        print("####misp in createObject: al_attr_type: ",al_attr_type)
        misp_object=pymisp.MISPObject(self.al2misp_mappings['objects'][al_attr_type]['mapto'])
        [attr,refs]=self.createAttributes('objects',al_attr_type, data)
        misp_object.add_attributes(attr)
        for obj_reference in refs.items():
            reference_uuid=self.findFileObjectBySha256(obj_reference['referenced_uuid'])['uuid']
            misp_object.add_reference(reference_uuid,obj_reference['relationship_type'])
        return misp_object
            
                    

    def createFileObjects(self):
        f_objects=[]
        for ontology_item in self.ontology_result[0]:
            f_objects.append(self.createObject('file',ontology_item))
            logging.warning("####misp createObject: ok")
        self.misp_objects = f_objects
        return f_objects
        
    def createEvent(self,**submission_attrs):
        event = pymisp.MISPEvent()
        event.info = 'Example event with domain and dst-ip'

        # Add attributes for domain and dst-ip
        event.add_attribute('domain', 'example.com')
        event.add_attribute('dst-ip', '192.168.1.1')

        # Add the event to MISP
        response = misp.add_event(event)



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