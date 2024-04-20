# def createObject(self,al_attr_type, data):
    #     print("####misp in createObject: al_attr_type: ",al_attr_type) 
    #     try:
    #         misp_object=pymisp.MISPObject(self.al2misp_mappings['objects'][al_attr_type]['to'])
    #     except Exception as e:
    #         print("error creating misp obj:",e)

    
    #     [attrs,obj_refs]=self.createAttributes('objects',al_attr_type, data)
        
    #     for attr_rel in [attr_item.to_dict() for attr_item in attrs]:
    #         if attr_rel['object_relation'] in self.object_name_fields:
    #             print('@@@@@ attr_rel: ', attr_rel['value'])
    #             misp_object.name=attr_rel['value']
    #     print("***      *   obj created:")
    #     print('-_-_-_-_ attrs: ')
    #     pprint(attrs)
    #     print("././././././/")
    #     try:
    #         #misp_object.add_attributes(attrs)
    #         for atrib_item in attrs:
    #             logging.warning("####add attribute to object :")
    #             print("______________ ret attr: :", atrib_item)
    #             ret_attr=misp_object.add_attribute(atrib_item.type,atrib_item.value)
                
    #     except Exception as e:
    #         print("<>>><>< eeee Error adding attribute to object:", e)
    #         print("attr type:",atrib_item.type," attr val: ",atrib_item.value)
    #     #misp_object.attributes=attrs
    #     #print(misp_object.attributes)
        
    #     print("====refs:",obj_refs)

    #     for obj_reference in obj_refs:
    #         references=self.findFileObjectBySha256(obj_reference['referenced_uuid'])
    #         #print("references:", references)
    #         try:
    #             for reference_item in references:
    #                 print("   ref uuid: ", reference_item)
    #                 ret_objref=misp_object.add_reference(reference_item, obj_reference['relationship_type'])
    #             print("==== createObject ret references:", ret_objref)
    #         except Exception as e:
    #             print("No references found", e)
    #         #print("obj_reference:", obj_reference)
    #     return misp_object





    def createAttributes_old(self,attr_scope,al_attr_type, data):
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
                        attributes.append(self.createAttributeWrapper(attr_scope, item_attr_val, **self.al2misp_mappings[attr_scope][al_attr_type][attr_k]))
                    elif self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'] == 'add_reference':
                        references.append({'referenced_uuid':attr_v, 'relationship_type':self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['to']})
                        #print("#### createObjectAttributes: references: ", references)
            elif (type(attr_v) == dict) and (attr_k == 'tags') and (len(attr_v)>0): 
                #print("?????????? createObjectAttributes elif tags: ", attr_k)
                for type_item,value_item in attr_v.items():
                    #print("in createObjectAttributes type: ", type_item, " val: ", value_item[0] ,  " type val: ",  type(value_item))
                    if type_item in self.al2misp_mappings[attr_scope][al_attr_type]:
                        #print("createObjectAttributes self.al2misp_mappings[attr_scope][al_attr_type][type_item] : ", self.al2misp_mappings[attr_scope][al_attr_type][type_item])
                        attributes.append(self.createAttributeWrapper(attr_scope, value_item[0], **self.al2misp_mappings[attr_scope][al_attr_type][type_item]))
            else:
                #print("-=-=createObjectAttributes else type attr_v:", type(self.al2misp_mappings[attr_scope][al_attr_type]))
                try:    
                    if attr_k in self.al2misp_mappings[attr_scope][al_attr_type]:
                        #pprint(self.al2misp_mappings[attr_scope][al_attr_type])
                        if self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'] == 'map':
                            #print("####createObjectAttributes: to: ",self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['to'])
                            attributes.append(self.createAttributeWrapper(attr_scope, attr_v, **self.al2misp_mappings[attr_scope][al_attr_type][attr_k]))
                        elif self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['action'] == 'add_reference':
                            references.append({'referenced_uuid':attr_v, 'relationship_type':self.al2misp_mappings[attr_scope][al_attr_type][attr_k]['to']})
                            #print("#### createObjectAttributes: references: ", references)
                except Exception as e:
                    print("Error createAttribute: ", e)
        #print("####misp in createAttributes :  attributes:",attributes)
        return [attributes,references]





    def createAttributeWrapper(self,attr_scope, attrib_val, **attrib_dict):
        print("createAttributeWrapper - scope:::::", attr_scope)
        if attr_scope == 'objects':
            attrib=self.createObjectAttribute( attrib_val, **attrib_dict)

        else:
            attrib=self.createEventAttribute(  attrib_val, **attrib_dict)

        #print("=======++++ in createAttributeWrapper: ")
        #pprint(attrib)
        #de creat toate campurile necesare pentru un attribut !!!!!!!!!!
        return attrib




    def createObjectAttribute(self, attrib_val, **attrib_dict):
        print("[][][][][] Create obj attr:", attrib_dict, " val: ", attrib_val)
        
        
        try:
            
            #attribute_def.from_dict(**{'type':attrib_type, 'value':attrib_val, 'object_relation':attrib_type})
            #print("attrib_def: ", attribute_def)
            attribute = pymisp.MISPObjectAttribute(pymisp.MISPAttribute())
            #print("attrib obj:",attribute)

            attribute.from_dict(attrib_dict['to'], attrib_val,**{'type':attrib_dict['obj_type']})
            print(",.,.,.,. obj attribute created: ", attribute)
        except Exception as e:
            print("Error creating obj attribute: ", e)
        print("[][][][][]  attr returned by createObjectAttribute: ", attribute)
        return attribute









