﻿using B2BApp.DTOs;
using B2BApp.Entities.Concrete;
using Core.Models.Concrete;
using MongoDB.Bson;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace B2BApp.Business.Abstract
{
    public interface ITedarikciService
    {

        void addTedarikci(Tedarikci Tedarikciler);
        void updateTedarikci(Tedarikci Tedarikciler, string TedarikciId);
        void deleteTedarikci(ObjectId objectId);
        Result<ICollection<Tedarikci>> getAll();
        Result<Tedarikci> getTedarikciById(ObjectId objectId);

    }
}
